package csrftoken

import "errors"

// MaxTx is the maximum number of live transactions in a TxStore. When it
// is reached, Add evicts the oldest transaction, which is most likely an
// abandoned form.
const MaxTx = 32

// ErrTxUnknown is returned by Remove when the token is valid but its
// transaction doesn't exist: it was already removed, or evicted. This
// happens when the user submits a form twice, or submits an older version
// of a form after going back in the browser history.
var ErrTxUnknown = errors.New("csrftoken: unknown transaction")

// TxStore holds the live transactions of a session: for each transaction,
// its id, expiration time and context. The context is any value the
// application wants to associate with the transaction, or nil. Storing a
// pointer avoids an allocation, since a non pointer value is boxed in an
// interface.
//
// A transaction is added with Add, which returns the token to put in the
// form, and removed with Remove, which verifies the token. To display a
// form again, for instance after an input error or for the next step of a
// form with multiple steps, Remove the transaction then Add it again with
// the returned expiration time. Each displayed version of a form thus has
// its own token, and only the last one is valid.
//
// The transactions are kept in a slice ordered by transaction id. The first
// eight transactions are stored in a scratch array inside the TxStore, so
// that a session with few transactions doesn't allocate. Transactions are
// searched sequentially, which is faster than a map for so few entries.
//
// The zero value is an empty store ready to use. Transaction ids start at 1.
//
// A TxStore is not safe for concurrent use: the caller must hold the
// session mutex. It must not be copied after first use, since its slice
// may point into its own scratch array.
type TxStore struct {
	entries []txEntry  // ordered by txid, initially scratch[:0]
	scratch [8]txEntry // storage of the first transactions
	last    uint64     // last transaction id
}

// txEntry is a transaction of a TxStore.
type txEntry struct {
	txid uint64
	exp  Expiration
	ctx  any
}

// Add adds a transaction with context ctx, expiring at exp, and returns the
// token created with tokens and bound to sid, and the transaction id, which
// may be logged. Expired transactions are purged, and if MaxTx transactions
// remain, the oldest one is evicted. On error, the store is unchanged.
func (t *TxStore) Add(tokens *Maker, sid []byte, exp Expiration, ctx any) (string, uint64, error) {
	now := timeNow().Unix() // read the clock once
	txid := t.last + 1
	tok, err := tokens.create(sid, txid, exp, now)
	if err != nil {
		return "", 0, err
	}
	t.last = txid
	if t.entries == nil {
		t.entries = t.scratch[:0]
	}
	t.purge(Expiration(now))
	if len(t.entries) >= MaxTx {
		t.removeAt(0) // the oldest transaction
	}
	t.entries = append(t.entries, txEntry{txid: txid, exp: exp, ctx: ctx})
	return tok, txid, nil
}

// Remove verifies token with tokens and sid, removes its transaction and
// returns its context, expiration time and transaction id. It returns the
// error of Verify if the token is invalid or expired, and ErrTxUnknown if
// the token is valid but its transaction doesn't exist. With ErrTxUnknown,
// the returned transaction id is the one carried by the token, which may
// be logged.
func (t *TxStore) Remove(tokens *Maker, token string, sid []byte) (any, Expiration, uint64, error) {
	txid, err := tokens.Verify(token, sid)
	if err != nil {
		return nil, 0, 0, err
	}
	i := t.index(txid)
	if i < 0 {
		return nil, 0, txid, ErrTxUnknown
	}
	e := t.entries[i]
	t.removeAt(i)
	return e.ctx, e.exp, txid, nil
}

// index returns the index of the transaction txid, or -1 if there is none.
func (t *TxStore) index(txid uint64) int {
	for i := range t.entries {
		if t.entries[i].txid == txid {
			return i
		}
	}
	return -1
}

// purge removes the transactions expired at time now, keeping the order.
// The freed entries are zeroed so that their contexts can be garbage
// collected.
func (t *TxStore) purge(now Expiration) {
	n := 0
	for _, e := range t.entries {
		if e.exp > now {
			t.entries[n] = e
			n++
		}
	}
	clear(t.entries[n:])
	t.entries = t.entries[:n]
}

// removeAt removes the entry at index i, keeping the order. The freed entry
// is zeroed so that its context can be garbage collected.
func (t *TxStore) removeAt(i int) {
	n := copy(t.entries[i:], t.entries[i+1:])
	t.entries[i+n] = txEntry{}
	t.entries = t.entries[:i+n]
}
