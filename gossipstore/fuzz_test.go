/*
FILE PATH:

	gossipstore/fuzz_test.go

DESCRIPTION:

	J1 — Fuzz the gossipstore.Append validation path. Property:
	Append never panics on arbitrary SignedEvent inputs; either
	accepts (valid wire shape + chain-discipline) or rejects
	with a typed error. Catches deserialization / state-machine
	bugs that example tests miss because they use fixed shapes.

	Run via:
	    go test -run=^$ -fuzz=^FuzzGossipStoreAppend$ \
	        -fuzztime=30s ./gossipstore/
*/
package gossipstore

import (
	"context"
	"testing"
	"time"

	"github.com/clearcompass-ai/attesta/gossip"
	badger "github.com/dgraph-io/badger/v4"
)

// FuzzGossipStoreAppend asserts: Append on arbitrary inputs
// returns a typed error OR succeeds; never panics.
func FuzzGossipStoreAppend(f *testing.F) {
	// Production-shaped seeds.
	f.Add("did:web:peer1", uint64(1), "originator-rotation", []byte("{}"))
	f.Add("did:web:peer1", uint64(2), "cosigned-tree-head", []byte(`{"root":"abc"}`))
	// Hostile seeds.
	f.Add("", uint64(0), "", []byte{})               // empty everything
	f.Add("did:web:peer1", uint64(0), "x", []byte{}) // empty body
	f.Add("\x00\x00", uint64(1<<63), "", []byte("..."))
	// Long originator should hit MaxOriginatorLen rejection.
	long := make([]byte, 1024)
	for i := range long {
		long[i] = 'a'
	}
	f.Add(string(long), uint64(1), "k", []byte("{}"))

	f.Fuzz(func(t *testing.T, originator string, lamport uint64, kind string, body []byte) {
		// Cap inputs to prevent runner OOM.
		if len(originator) > 4096 || len(kind) > 1024 || len(body) > 65535 {
			return
		}
		opts := badger.DefaultOptions("").
			WithInMemory(true).
			WithLoggingLevel(badger.ERROR)
		db, err := badger.Open(opts)
		if err != nil {
			t.Fatalf("badger open: %v", err)
		}
		defer db.Close()

		store, err := New(Config{DB: db, GCInterval: -1})
		if err != nil {
			t.Fatalf("gossipstore New: %v", err)
		}

		ev := gossip.SignedEvent{
			Originator:  originator,
			LamportTime: lamport,
			Kind:        gossip.Kind(kind),
			Body:        body,
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		// Property: never panic. Errors are fine; success is fine.
		_ = store.Append(ctx, ev)
	})
}
