package csrftoken

import (
	"errors"
	"testing"
)

// mustAdd adds a transaction and returns its token, or fails the test.
func mustAdd(t *testing.T, s *TxStore, m *Maker, exp Expiration, ctx any) string {
	t.Helper()
	tok, _, err := s.Add(m, testSID, exp, ctx)
	if err != nil {
		t.Fatalf("Add: unexpected error: %v", err)
	}
	return tok
}

func TestTxStoreAddRemove(t *testing.T) {
	now := testNow
	setNow(t, &now)
	m := newTestMaker(t)
	var s TxStore
	tok, txid, err := s.Add(m, testSID, Expiration(now+60), "ctx")
	if err != nil || txid != 1 {
		t.Fatalf("Add: got txid %d, %v, want 1, nil", txid, err)
	}
	ctx, exp, txid2, err := s.Remove(m, tok, testSID)
	if err != nil || ctx != "ctx" || exp != Expiration(now+60) || txid2 != txid {
		t.Errorf("Remove: got %v, %d, %d, %v, want ctx, %d, %d, nil", ctx, exp, txid2, err, now+60, txid)
	}
	// The transaction id is returned with ErrTxUnknown, for logging.
	if _, _, txid3, err := s.Remove(m, tok, testSID); !errors.Is(err, ErrTxUnknown) || txid3 != txid {
		t.Errorf("second Remove: got %d, %v, want %d, %v", txid3, err, txid, ErrTxUnknown)
	}
}

func TestTxStoreScratch(t *testing.T) {
	now := testNow
	setNow(t, &now)
	m := newTestMaker(t)
	var s TxStore
	mustAdd(t, &s, m, Expiration(now+60), nil)
	if &s.entries[0] != &s.scratch[0] {
		t.Error("first transaction is not stored in the scratch array")
	}
}

func TestTxStoreIDs(t *testing.T) {
	now := testNow
	setNow(t, &now)
	m := newTestMaker(t)
	var s TxStore
	for want := uint64(1); want <= 3; want++ {
		tok, txid, err := s.Add(m, testSID, Expiration(now+60), nil)
		if err != nil || txid != want {
			t.Fatalf("Add: got txid %d, %v, want %d, nil", txid, err, want)
		}
		if got, err := m.Verify(tok, testSID); err != nil || got != want {
			t.Errorf("Verify: got txid %d, %v, want %d, nil", got, err, want)
		}
	}
}

func TestTxStoreAddError(t *testing.T) {
	now := testNow
	setNow(t, &now)
	m := newTestMaker(t)
	var s TxStore
	if _, _, err := s.Add(m, nil, Expiration(now+60), "a"); !errors.Is(err, ErrSession) {
		t.Errorf("empty sid: got error %v, want %v", err, ErrSession)
	}
	if _, _, err := s.Add(m, testSID, Expiration(now), "a"); !errors.Is(err, ErrExp) {
		t.Errorf("exp now: got error %v, want %v", err, ErrExp)
	}
	if s.last != 0 || len(s.entries) != 0 {
		t.Errorf("store changed on error: last %d, %d transactions", s.last, len(s.entries))
	}
}

func TestTxStoreRemoveInvalid(t *testing.T) {
	now := testNow
	setNow(t, &now)
	m := newTestMaker(t)
	var s TxStore
	tok := mustAdd(t, &s, m, Expiration(now+60), "a")
	if _, _, _, err := s.Remove(m, tok, []byte("other-session")); !errors.Is(err, ErrInvalid) {
		t.Errorf("other session: got error %v, want %v", err, ErrInvalid)
	}
	now += 60
	if _, _, _, err := s.Remove(m, tok, testSID); !errors.Is(err, ErrExpired) {
		t.Errorf("expired: got error %v, want %v", err, ErrExpired)
	}
}

func TestTxStoreRenew(t *testing.T) {
	// Display a form again: Remove then Add with the returned expiration time.
	now := testNow
	setNow(t, &now)
	m := newTestMaker(t)
	var s TxStore
	tok1 := mustAdd(t, &s, m, Expiration(now+60), "first")
	now += 10
	ctx, exp, _, err := s.Remove(m, tok1, testSID)
	if err != nil || ctx != "first" {
		t.Fatalf("Remove: got %v, %v, want first, nil", ctx, err)
	}
	tok2 := mustAdd(t, &s, m, exp, "second")
	if _, _, _, err := s.Remove(m, tok1, testSID); !errors.Is(err, ErrTxUnknown) {
		t.Errorf("previous version: got error %v, want %v", err, ErrTxUnknown)
	}
	ctx, exp2, _, err := s.Remove(m, tok2, testSID)
	if err != nil || ctx != "second" || exp2 != exp {
		t.Errorf("last version: got %v, %d, %v, want second, %d, nil", ctx, exp2, err, exp)
	}
}

func TestTxStoreRemoveMiddle(t *testing.T) {
	now := testNow
	setNow(t, &now)
	m := newTestMaker(t)
	var s TxStore
	toks := make([]string, 5)
	for i := range toks {
		toks[i] = mustAdd(t, &s, m, Expiration(now+60), i)
	}
	if _, _, _, err := s.Remove(m, toks[2], testSID); err != nil {
		t.Fatalf("Remove: unexpected error: %v", err)
	}
	checkOrdered(t, &s)
	if s.scratch[4] != (txEntry{}) {
		t.Error("freed entry is not zeroed")
	}
	// The other transactions are kept.
	for _, i := range []int{0, 1, 3, 4} {
		if ctx, _, _, err := s.Remove(m, toks[i], testSID); err != nil || ctx != i {
			t.Errorf("Remove(%d): got %v, %v, want %d, nil", i, ctx, err, i)
		}
	}
}

func TestTxStorePurge(t *testing.T) {
	now := testNow
	setNow(t, &now)
	m := newTestMaker(t)
	var s TxStore
	mustAdd(t, &s, m, Expiration(now+1), "short")
	long := mustAdd(t, &s, m, Expiration(now+3600), "long")
	mustAdd(t, &s, m, Expiration(now+1), "short")
	now += 10
	mustAdd(t, &s, m, Expiration(now+3600), "new") // purges the two short transactions
	if len(s.entries) != 2 {
		t.Fatalf("after purge: got %d transactions, want 2", len(s.entries))
	}
	checkOrdered(t, &s)
	for i := len(s.entries); i < len(s.scratch); i++ {
		if s.scratch[i] != (txEntry{}) {
			t.Errorf("freed entry %d is not zeroed", i)
		}
	}
	if ctx, _, _, err := s.Remove(m, long, testSID); err != nil || ctx != "long" {
		t.Errorf("Remove(long): got %v, %v, want long, nil", ctx, err)
	}
}

func TestTxStoreEviction(t *testing.T) {
	now := testNow
	setNow(t, &now)
	m := newTestMaker(t)
	var s TxStore
	toks := make([]string, MaxTx+1)
	for i := range toks {
		toks[i] = mustAdd(t, &s, m, Expiration(now+60), i)
	}
	if len(s.entries) != MaxTx {
		t.Errorf("got %d transactions, want %d", len(s.entries), MaxTx)
	}
	checkOrdered(t, &s)
	if _, _, _, err := s.Remove(m, toks[0], testSID); !errors.Is(err, ErrTxUnknown) {
		t.Errorf("oldest transaction: got error %v, want %v", err, ErrTxUnknown)
	}
	if ctx, _, _, err := s.Remove(m, toks[MaxTx], testSID); err != nil || ctx != MaxTx {
		t.Errorf("newest transaction: got %v, %v, want %d, nil", ctx, err, MaxTx)
	}
}

// checkOrdered checks that the transactions are ordered by txid.
func checkOrdered(t *testing.T, s *TxStore) {
	t.Helper()
	for i := 1; i < len(s.entries); i++ {
		if s.entries[i-1].txid >= s.entries[i].txid {
			t.Fatalf("transactions not ordered at index %d", i)
		}
	}
}
