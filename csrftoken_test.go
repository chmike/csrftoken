package csrftoken

import (
	"errors"
	"math"
	"strings"
	"testing"
	"time"
)

var (
	testSeed = []byte("0123456789abcdef0123456789abcdef") // SeedLen bytes
	testSID  = []byte("session-id")
)

// testNow is an arbitrary unix time used as current time.
const testNow int64 = 1_790_000_000

// setNow makes timeNow return *now until the end of the test. The test
// moves the time forward by modifying *now. Tests using setNow must not
// run in parallel.
func setNow(t testing.TB, now *int64) {
	t.Helper()
	orig := timeNow
	timeNow = func() time.Time { return time.Unix(*now, 0) }
	t.Cleanup(func() { timeNow = orig })
}

func newTestMaker(t testing.TB) *Maker {
	t.Helper()
	m, err := NewMaker(testSeed)
	if err != nil {
		t.Fatalf("NewMaker: unexpected error: %v", err)
	}
	return m
}

// signedToken returns the encoded token made of payload followed by its
// valid MAC for testSID. It is used to forge tokens with a valid MAC but an
// invalid content.
func signedToken(m *Maker, payload []byte) string {
	s := m.pool.Get().(*state)
	defer m.pool.Put(s)
	buf := append(append([]byte(nil), payload...), s.mac(payload, testSID)...)
	return b64.EncodeToString(buf)
}

func TestNewMaker(t *testing.T) {
	for _, n := range []int{0, SeedLen - 1, SeedLen + 1} {
		if _, err := NewMaker(make([]byte, n)); !errors.Is(err, ErrSeed) {
			t.Errorf("NewMaker with %d bytes seed: got error %v, want %v", n, err, ErrSeed)
		}
	}
	m1, m2 := newTestMaker(t), newTestMaker(t)
	if m1.key != m2.key {
		t.Error("same seed: got different keys")
	}
	m3, err := NewMaker(make([]byte, SeedLen))
	if err != nil {
		t.Fatalf("NewMaker: unexpected error: %v", err)
	}
	if m1.key == m3.key {
		t.Error("different seeds: got same keys")
	}
}

func TestMustNewMaker(t *testing.T) {
	if m := MustNewMaker(testSeed); m == nil {
		t.Fatal("MustNewMaker: got nil maker")
	}
	defer func() {
		if recover() == nil {
			t.Error("MustNewMaker with invalid seed: expected a panic")
		}
	}()
	MustNewMaker(nil)
}

func TestExpiration(t *testing.T) {
	now := testNow
	setNow(t, &now)
	if got, want := ExpireIn(90*time.Second+500*time.Millisecond), Expiration(testNow+90); got != want {
		t.Errorf("ExpireIn: got %d, want %d", got, want)
	}
	if got, want := Expiration(testNow).Time(), time.Unix(testNow, 0); !got.Equal(want) {
		t.Errorf("Time: got %v, want %v", got, want)
	}
}

func TestCreateVerify(t *testing.T) {
	now := testNow
	setNow(t, &now)
	m := newTestMaker(t)
	tok, err := m.Create(testSID, 42, Expiration(now+60))
	if err != nil {
		t.Fatalf("Create: unexpected error: %v", err)
	}
	txid, err := m.Verify(tok, testSID)
	if err != nil {
		t.Fatalf("Verify: unexpected error: %v", err)
	}
	if txid != 42 {
		t.Errorf("Verify: got txid %d, want 42", txid)
	}
}

func TestAppendCreate(t *testing.T) {
	now := testNow
	setNow(t, &now)
	m := newTestMaker(t)
	exp := Expiration(now + 60)
	want, err := m.Create(testSID, 42, exp)
	if err != nil {
		t.Fatalf("Create: unexpected error: %v", err)
	}
	const prefix = "prefix:"
	tests := []struct {
		name string
		dst  []byte
	}{
		{"nil dst", nil},
		{"dst to grow", []byte(prefix)},
		{"dst with capacity", append(make([]byte, 0, 64), prefix...)},
	}
	for _, tt := range tests {
		p := string(tt.dst)
		got, err := m.AppendCreate(tt.dst, testSID, 42, exp)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", tt.name, err)
		}
		if string(got) != p+want {
			t.Errorf("%s: got %q, want %q", tt.name, got, p+want)
		}
	}

	// dst is returned unchanged on error
	got, err := m.AppendCreate([]byte(prefix), nil, 42, exp)
	if !errors.Is(err, ErrSession) || string(got) != prefix {
		t.Errorf("error: got %q, %v, want %q, %v", got, err, prefix, ErrSession)
	}
}

func TestCreateErrors(t *testing.T) {
	now := testNow
	setNow(t, &now)
	m := newTestMaker(t)
	tests := []struct {
		name string
		sid  []byte
		exp  Expiration
		want error
	}{
		{"nil sid", nil, Expiration(now + 60), ErrSession},
		{"empty sid", []byte{}, Expiration(now + 60), ErrSession},
		{"exp in the past", testSID, Expiration(now - 1), ErrExp},
		{"exp now", testSID, Expiration(now), ErrExp},
		{"exp above max", testSID, Expiration(now + maxTTLSec + 1), ErrExp},
	}
	for _, tt := range tests {
		if _, err := m.Create(tt.sid, 1, tt.exp); !errors.Is(err, tt.want) {
			t.Errorf("%s: got error %v, want %v", tt.name, err, tt.want)
		}
	}
	for _, exp := range []Expiration{Expiration(now + 1), Expiration(now + maxTTLSec)} {
		if _, err := m.Create(testSID, 1, exp); err != nil {
			t.Errorf("exp now%+d: unexpected error: %v", int64(exp)-now, err)
		}
	}
}

func TestTxIDRoundTrip(t *testing.T) {
	now := testNow
	setNow(t, &now)
	m := newTestMaker(t)
	values := []uint64{0, 1, 127, 128, 1<<14 - 1, 1 << 14, 1<<56 - 1, 1 << 56, math.MaxUint64}
	for _, v := range values {
		tok, err := m.Create(testSID, v, Expiration(now+3600))
		if err != nil {
			t.Fatalf("txid %d: Create: unexpected error: %v", v, err)
		}
		if len(tok) < b64.EncodedLen(minTokenLen) || len(tok) > maxEncLen {
			t.Errorf("txid %d: token length %d out of range", v, len(tok))
		}
		got, err := m.Verify(tok, testSID)
		if err != nil {
			t.Fatalf("txid %d: Verify: unexpected error: %v", v, err)
		}
		if got != v {
			t.Errorf("txid %d: got %d", v, got)
		}
	}
}

func TestTokenLength(t *testing.T) {
	now := testNow
	setNow(t, &now)
	m := newTestMaker(t)
	tests := []struct {
		txid uint64
		want int
	}{
		{0, 23},
		{math.MaxUint64, 34},
	}
	for _, tt := range tests {
		tok, err := m.Create(testSID, tt.txid, Expiration(now+3600))
		if err != nil {
			t.Fatalf("txid %d: unexpected error: %v", tt.txid, err)
		}
		if len(tok) != tt.want {
			t.Errorf("txid %d: got token length %d, want %d", tt.txid, len(tok), tt.want)
		}
	}
}

func TestVerifyErrors(t *testing.T) {
	now := testNow
	setNow(t, &now)
	m := newTestMaker(t)
	tok, err := m.Create(testSID, 1234, Expiration(now+3600))
	if err != nil {
		t.Fatalf("Create: unexpected error: %v", err)
	}

	// tampered changes one character in the middle of the token.
	c := byte('A')
	if tok[5] == c {
		c = 'B'
	}
	tampered := tok[:5] + string(c) + tok[6:]

	// short decodes to fewer than minTokenLen bytes despite its valid string
	// length, because the decoder ignores new line characters.
	short := b64.EncodeToString(make([]byte, minTokenLen-1)) + "\n"

	tests := []struct {
		name  string
		token string
		sid   []byte
		want  error
	}{
		{"empty sid", tok, nil, ErrSession},
		{"empty token", "", testSID, ErrInvalid},
		{"too short", tok[:b64.EncodedLen(minTokenLen)-1], testSID, ErrInvalid},
		{"too long", strings.Repeat("A", maxEncLen+1), testSID, ErrInvalid},
		{"invalid character", "!" + tok[1:], testSID, ErrInvalid},
		{"too few decoded bytes", short, testSID, ErrInvalid},
		{"other session", tok, []byte("other-session"), ErrInvalid},
		{"tampered", tampered, testSID, ErrInvalid},
		{"non canonical txid", signedToken(m, []byte{0, 0, 0, 0, 0x80, 0x00}), testSID, ErrInvalid},
		{"trailing byte after txid", signedToken(m, []byte{0, 0, 0, 0, 0x01, 0x02}), testSID, ErrInvalid},
	}
	for _, tt := range tests {
		if _, err := m.Verify(tt.token, tt.sid); !errors.Is(err, tt.want) {
			t.Errorf("%s: got error %v, want %v", tt.name, err, tt.want)
		}
	}
}

func TestVerifyExpiration(t *testing.T) {
	now := testNow
	setNow(t, &now)
	m := newTestMaker(t)
	tok, err := m.Create(testSID, 1, Expiration(now+60))
	if err != nil {
		t.Fatalf("Create: unexpected error: %v", err)
	}
	now = testNow + 59
	if _, err := m.Verify(tok, testSID); err != nil {
		t.Errorf("before expiration: unexpected error: %v", err)
	}
	for _, at := range []int64{testNow + 60, testNow + 61, testNow + 1e6} {
		now = at
		if _, err := m.Verify(tok, testSID); !errors.Is(err, ErrExpired) {
			t.Errorf("now = exp%+d: got error %v, want %v", at-testNow-60, err, ErrExpired)
		}
	}
}

func TestVerifyExpirationTooFar(t *testing.T) {
	// A token whose expiration is further than MaxTTL from now can't be
	// created at now. It is made here by creating it in the future.
	now := testNow + 10
	setNow(t, &now)
	m := newTestMaker(t)
	tok, err := m.Create(testSID, 1, Expiration(now+maxTTLSec))
	if err != nil {
		t.Fatalf("Create: unexpected error: %v", err)
	}
	now = testNow
	if _, err := m.Verify(tok, testSID); !errors.Is(err, ErrInvalid) {
		t.Errorf("got error %v, want %v", err, ErrInvalid)
	}
}

func TestVerifyExpirationWrap(t *testing.T) {
	// The expiration time wraps around 2^32 while the token is valid.
	start := int64(1)<<32 - 10
	now := start
	setNow(t, &now)
	m := newTestMaker(t)
	tok, err := m.Create(testSID, 1, Expiration(start+100))
	if err != nil {
		t.Fatalf("Create: unexpected error: %v", err)
	}
	for _, at := range []int64{start, start + 50, start + 99} {
		now = at
		if _, err := m.Verify(tok, testSID); err != nil {
			t.Errorf("start%+d: unexpected error: %v", at-start, err)
		}
	}
	now = start + 100
	if _, err := m.Verify(tok, testSID); !errors.Is(err, ErrExpired) {
		t.Errorf("at expiration: got error %v, want %v", err, ErrExpired)
	}
}

func TestUvarintRoundTrip(t *testing.T) {
	type test struct {
		v uint64
		n int
	}
	tests := []test{{0, 1}}
	for l := 1; l <= 8; l++ {
		tests = append(tests, test{uint64(1)<<(7*l) - 1, l}, test{uint64(1) << (7 * l), l + 1})
	}
	tests = append(tests, test{math.MaxUint64, 9})
	for _, tt := range tests {
		var b [maxTxIDLen]byte
		if n := putUvarint(b[:], tt.v); n != tt.n {
			t.Errorf("putUvarint(%#x): got %d bytes, want %d", tt.v, n, tt.n)
			continue
		}
		v, n := uvarint(b[:tt.n])
		if v != tt.v || n != tt.n {
			t.Errorf("uvarint of %#x: got %#x, %d bytes, want %#x, %d bytes", tt.v, v, n, tt.v, tt.n)
		}
	}
}

func TestUvarintInvalid(t *testing.T) {
	cont8 := []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80}
	tests := []struct {
		name string
		b    []byte
	}{
		{"empty", nil},
		{"truncated", []byte{0x80}},
		{"truncated after 8 bytes", cont8},
		{"zero last byte", []byte{0x80, 0x00}},
		{"zero 9th byte", append(append([]byte(nil), cont8...), 0x00)},
	}
	for _, tt := range tests {
		if v, n := uvarint(tt.b); v != 0 || n != 0 {
			t.Errorf("%s: got %#x, %d, want 0, 0", tt.name, v, n)
		}
	}
}
