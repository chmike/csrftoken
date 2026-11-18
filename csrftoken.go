// Package csrftoken creates and verifies short CSRF tokens.
//
// A token is bound to a session id and carries a transaction id. It is
// verified without any database access: the server recomputes its MAC from
// the token content and the session id of the request. A token is only
// valid with the session id it was created for, until its expiration time.
//
// Token layout, before base64url encoding (no padding):
//
//	exp  : 4 bytes, expiration time as unix seconds modulo 2^32, big endian
//	txid : 1 to 9 bytes, transaction id, LEB128 variant limited to 9 bytes
//	mac  : 12 bytes, HMAC-SHA256(key, exp ‖ txid ‖ sid) truncated
//
// A token is 17 to 25 bytes long, thus 23 to 34 characters once encoded.
//
// The session id is not stored in the token. It must be provided by the
// caller to Create and Verify, typically from the session cookie. An empty
// session id is rejected because a token bound to nothing doesn't protect
// against CSRF.
//
// The expiration time is stored modulo 2^32 and compared with a signed 32
// bit difference, so wrapping is harmless as long as the time to live is
// below 2^31 seconds. MaxTTL is far below this limit.
package csrftoken

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"sync"
	"time"
)

// SeedLen is the byte length of the seed. It is the same seed as the one
// of the securecookie key store.
const SeedLen = 32

// MaxTTL is the maximum time to live of a token. A token can't outlive the
// session it is bound to, so there is no use to exceed the maximum session
// lifetime.
const MaxTTL = 400 * 24 * time.Hour

// kdfInfo is the HKDF info used to derive the token key from the seed. It
// differs from the securecookie info, so the keys are independent. Changing
// the token format requires changing this info, which invalidates tokens
// of the previous format.
const kdfInfo = "csrftoken v1 key"

const (
	expLen      = 4
	maxTxIDLen  = 9
	macLen      = 12
	minTokenLen = expLen + 1 + macLen
	maxTokenLen = expLen + maxTxIDLen + macLen
	maxEncLen   = (maxTokenLen*8 + 5) / 6 // base64 length without padding
	maxTTLSec   = int64(MaxTTL / time.Second)
)

// b64 rejects encodings with non zero trailing bits.
var b64 = base64.RawURLEncoding.Strict()

// timeNow returns the current time. Tests replace it.
var timeNow = time.Now

var (
	// ErrSeed is returned when the seed doesn't have SeedLen bytes.
	ErrSeed = errors.New("csrftoken: invalid seed length")
	// ErrExp is returned when the expiration time is less than a second
	// from now, or more than MaxTTL from now.
	ErrExp = errors.New("csrftoken: expiration time out of range")
	// ErrSession is returned when the session id is empty.
	ErrSession = errors.New("csrftoken: empty session id")
	// ErrInvalid is returned when the token is malformed, forged, or bound
	// to another session.
	ErrInvalid = errors.New("csrftoken: invalid token")
	// ErrExpired is returned when the token is authentic but expired.
	ErrExpired = errors.New("csrftoken: expired token")
)

// Expiration is an expiration time in unix seconds.
type Expiration int64

// ExpireIn returns the expiration time ttl from now, truncated to the second.
func ExpireIn(ttl time.Duration) Expiration {
	return Expiration(timeNow().Unix() + int64(ttl/time.Second))
}

// Time returns the expiration time as a time.Time.
func (e Expiration) Time() time.Time {
	return time.Unix(int64(e), 0)
}

// Maker creates and verifies tokens. It only holds the key derived from the
// seed, not the seed itself, so it can't be used to derive the securecookie
// keys. A Maker may be used by different goroutines. It must not be copied,
// use the pointer returned by NewMaker.
type Maker struct {
	key  [sha256.Size]byte
	pool sync.Pool // of *state
}

// state holds an HMAC and the buffers used to create or verify a token.
// States are recycled with a sync.Pool to avoid allocations. The buffers
// are in the state, thus on the heap, because the slices passed to the
// HMAC methods escape: they are interface method calls.
type state struct {
	hmac hash.Hash
	buf  [maxTokenLen]byte
	sum  [sha256.Size]byte
}

// mac returns the first macLen bytes of HMAC(key, payload ‖ sid). payload
// is unambiguous because exp has a fixed length and txid is self
// delimiting, and sid comes last. The returned slice is overwritten by the
// next call.
//
// Reset restores the HMAC state saved after hashing the padded key, so the
// key is not hashed again at each call.
func (s *state) mac(payload, sid []byte) []byte {
	s.hmac.Reset()
	s.hmac.Write(payload)
	s.hmac.Write(sid)
	return s.hmac.Sum(s.sum[:0])[:macLen]
}

// NewMaker returns a token maker whose key is derived from seed with
// HKDF-SHA256 (RFC 5869), using a zero salt and kdfInfo as info.
func NewMaker(seed []byte) (*Maker, error) {
	if len(seed) != SeedLen {
		return nil, fmt.Errorf("%w: %d bytes, expected %d", ErrSeed, len(seed), SeedLen)
	}
	// HKDF-Extract with a zero salt
	mac := hmac.New(sha256.New, make([]byte, sha256.Size))
	mac.Write(seed)
	var prk [sha256.Size]byte
	mac.Sum(prk[:0])
	// HKDF-Expand for a single block: HMAC(prk, info ‖ 0x01)
	mac = hmac.New(sha256.New, prk[:])
	mac.Write([]byte(kdfInfo))
	mac.Write([]byte{1})
	m := &Maker{}
	mac.Sum(m.key[:0])
	m.pool.New = func() any {
		return &state{hmac: hmac.New(sha256.New, m.key[:])}
	}
	return m, nil
}

// MustNewMaker panics if NewMaker returns a non-nil error, otherwise returns
// the token maker. The intended use is to instantiate the maker as a global
// variable.
func MustNewMaker(seed []byte) *Maker {
	m, err := NewMaker(seed)
	if err != nil {
		panic(err)
	}
	return m
}

// Create returns a token bound to sid, carrying txid, and expiring at exp.
// exp must be at least one second and at most MaxTTL from now.
func (m *Maker) Create(sid []byte, txid uint64, exp Expiration) (string, error) {
	return m.create(sid, txid, exp, timeNow().Unix())
}

// AppendCreate is like Create, but appends the token to dst and returns the
// extended slice. It doesn't allocate when dst has enough capacity. On
// error, dst is returned unchanged.
func (m *Maker) AppendCreate(dst, sid []byte, txid uint64, exp Expiration) ([]byte, error) {
	return m.appendCreate(dst, sid, txid, exp, timeNow().Unix())
}

// create is Create with now, the current unix time, as parameter. It allows
// a caller that already read the clock to avoid reading it again, which
// costs about 30 ns.
func (m *Maker) create(sid []byte, txid uint64, exp Expiration, now int64) (string, error) {
	var buf [maxEncLen]byte // on the stack, the string conversion is the only allocation
	b, err := m.appendCreate(buf[:0], sid, txid, exp, now)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// appendCreate is AppendCreate with now, the current unix time, as parameter.
func (m *Maker) appendCreate(dst, sid []byte, txid uint64, exp Expiration, now int64) ([]byte, error) {
	if len(sid) == 0 {
		return dst, ErrSession
	}
	if d := int64(exp) - now; d < 1 || d > maxTTLSec {
		return dst, ErrExp
	}
	s := m.pool.Get().(*state)
	defer m.pool.Put(s)
	b := s.buf[:]
	binary.BigEndian.PutUint32(b[:expLen], uint32(exp)) // modulo 2^32
	n := expLen + putUvarint(b[expLen:], txid)
	n += copy(b[n:], s.mac(b[:n], sid))
	return appendBase64(dst, b[:n]), nil
}

// Verify checks that token is authentic, bound to sid and not expired, and
// returns the transaction id it carries.
func (m *Maker) Verify(token string, sid []byte) (uint64, error) {
	if len(sid) == 0 {
		return 0, ErrSession
	}
	if len(token) < b64.EncodedLen(minTokenLen) || len(token) > maxEncLen {
		return 0, ErrInvalid
	}
	s := m.pool.Get().(*state)
	defer m.pool.Put(s)
	n, err := b64.Decode(s.buf[:], []byte(token))
	if err != nil || n < minTokenLen {
		return 0, ErrInvalid
	}

	// Check the MAC first, so that any later error concerns an authentic token.
	payload := s.buf[:n-macLen]
	if !hmac.Equal(s.mac(payload, sid), s.buf[n-macLen:n]) {
		return 0, ErrInvalid
	}

	txid, k := uvarint(payload[expLen:])
	if k == 0 || expLen+k != len(payload) {
		return 0, ErrInvalid // can only happen with a bug, the MAC is valid
	}

	// Signed difference modulo 2^32 between the expiration time and now.
	exp := binary.BigEndian.Uint32(payload[:expLen])
	d := int64(int32(exp - uint32(timeNow().Unix())))
	if d <= 0 {
		return 0, ErrExpired
	}
	if d > maxTTLSec {
		return 0, ErrInvalid // can only happen with a bug or a large clock change
	}
	return txid, nil
}

// appendBase64 appends the base64url encoding of src, without padding, to
// dst and returns the extended slice. dst is grown if needed.
func appendBase64(dst, src []byte) []byte {
	n := b64.EncodedLen(len(src))
	if cap(dst)-len(dst) < n {
		dst = append(make([]byte, 0, len(dst)+n), dst...)
	}
	b64.Encode(dst[len(dst):len(dst)+n], src)
	return dst[:len(dst)+n]
}

// putUvarint encodes v in b and returns the number of bytes written. The
// encoding is a LEB128 variant limited to 9 bytes: each of the first 8
// bytes holds 7 bits of v, low order first, with the most significant bit
// set when more bytes follow; the 9th byte holds the 8 remaining high
// order bits. b must have at least maxTxIDLen bytes.
func putUvarint(b []byte, v uint64) int {
	for i := 0; i < 8; i++ {
		if v < 0x80 {
			b[i] = byte(v)
			return i + 1
		}
		b[i] = byte(v) | 0x80
		v >>= 7
	}
	b[8] = byte(v)
	return 9
}

// uvarint decodes a value encoded by putUvarint at the start of b and
// returns the value and the number of bytes read. It returns 0, 0 if b is
// truncated or if the encoding is not canonical, that is when a multi-byte
// encoding ends with a zero byte.
func uvarint(b []byte) (uint64, int) {
	var v uint64
	for i := 0; i < 8 && i < len(b); i++ {
		c := b[i]
		v |= uint64(c&0x7F) << (7 * i)
		if c < 0x80 {
			if c == 0 && i > 0 {
				return 0, 0 // not canonical
			}
			return v, i + 1
		}
	}
	if len(b) < 9 || b[8] == 0 {
		return 0, 0 // truncated or not canonical
	}
	return v | uint64(b[8])<<56, 9
}
