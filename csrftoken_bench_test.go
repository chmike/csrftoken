package csrftoken

import (
	"math"
	"strconv"
	"testing"
	"time"
)

// Package level sinks prevent the compiler from optimizing the calls away.
var (
	sinkToken string
	sinkBytes []byte
	sinkTxID  uint64
	sinkErr   error
)

// benchTxIDs are transaction ids giving the shortest, a typical, and the
// longest token.
var benchTxIDs = []uint64{1, 1 << 20, math.MaxUint64}

func BenchmarkCreate(b *testing.B) {
	m := MustNewMaker(testSeed)
	exp := ExpireIn(time.Hour)
	for _, txid := range benchTxIDs {
		b.Run("txid="+strconv.FormatUint(txid, 10), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				sinkToken, sinkErr = m.Create(testSID, txid, exp)
			}
		})
	}
}

func BenchmarkAppendCreate(b *testing.B) {
	m := MustNewMaker(testSeed)
	exp := ExpireIn(time.Hour)
	dst := make([]byte, 0, maxEncLen)
	for _, txid := range benchTxIDs {
		b.Run("txid="+strconv.FormatUint(txid, 10), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				sinkBytes, sinkErr = m.AppendCreate(dst[:0], testSID, txid, exp)
			}
		})
	}
}

func BenchmarkVerify(b *testing.B) {
	m := MustNewMaker(testSeed)
	exp := ExpireIn(time.Hour)
	for _, txid := range benchTxIDs {
		tok, err := m.Create(testSID, txid, exp)
		if err != nil {
			b.Fatalf("Create: unexpected error: %v", err)
		}
		b.Run("txid="+strconv.FormatUint(txid, 10), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				sinkTxID, sinkErr = m.Verify(tok, testSID)
			}
		})
	}
}

// BenchmarkVerifyInvalid measures the rejection of a token bound to another
// session, which is the cost of a CSRF attempt.
func BenchmarkVerifyInvalid(b *testing.B) {
	m := MustNewMaker(testSeed)
	tok, err := m.Create(testSID, 1<<20, ExpireIn(time.Hour))
	if err != nil {
		b.Fatalf("Create: unexpected error: %v", err)
	}
	other := []byte("other-session")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sinkTxID, sinkErr = m.Verify(tok, other)
	}
}

// BenchmarkTxStore measures a form cycle, Add then Remove, with a few other
// live transactions in the store. The only allocation is the token string
// returned by Add.
func BenchmarkTxStore(b *testing.B) {
	m := MustNewMaker(testSeed)
	exp := ExpireIn(time.Hour)
	var s TxStore
	for i := 0; i < 4; i++ {
		if _, _, err := s.Add(m, testSID, exp, nil); err != nil {
			b.Fatalf("Add: unexpected error: %v", err)
		}
	}
	ctx := &struct{ name string }{"form"} // a pointer is not boxed
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		tok, _, err := s.Add(m, testSID, exp, ctx)
		if err != nil {
			b.Fatalf("Add: unexpected error: %v", err)
		}
		_, _, _, sinkErr = s.Remove(m, tok, testSID)
	}
}
