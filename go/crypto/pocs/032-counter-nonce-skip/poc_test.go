// PoC for finding 032 — FIPS GCMWithCounterNonce accepts skipped counters.
//
// crypto/internal/fips140/aes/gcm.GCMWithCounterNonce.Seal documents that
// each subsequent call must increment the counter by exactly one, but the
// pre-patch implementation only rejects counters strictly less than g.next.
// A sequence such as 0 then 2 silently succeeds, even though 1 was skipped.
//
// This test exercises the path with FIPS 140 mode enabled. Place this file
// in /private/tmp/go/src/crypto/cipher/ and run:
//
//   cd $(go env GOROOT)/src/crypto/cipher && \
//     GODEBUG=fips140=on go test -run TestPoC032 -v
//
// If the bug is present the test passes; the second Seal at counter 2
// (which skips counter 1) does not panic.

package cipher_test

import (
	"crypto/internal/fips140"
	fipsaes "crypto/internal/fips140/aes"
	"crypto/internal/fips140/aes/gcm"
	"encoding/binary"
	"testing"
)

func TestPoC032CounterNonceSkip(t *testing.T) {
	if !fips140.Enabled {
		t.Skip("FIPS mode required: re-run with GODEBUG=fips140=on")
	}

	key := make([]byte, 16)
	block, err := fipsaes.New(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := gcm.NewGCMWithCounterNonce(block)
	if err != nil {
		t.Fatal(err)
	}

	mkNonce := func(counter uint64) []byte {
		n := make([]byte, 12)
		copy(n, []byte("PoC!"))
		binary.BigEndian.PutUint64(n[4:], counter)
		return n
	}

	caught := func(fn func()) (panicked bool) {
		defer func() {
			if recover() != nil {
				panicked = true
			}
		}()
		fn()
		return
	}

	if caught(func() { aead.Seal(nil, mkNonce(0), []byte("a"), nil) }) {
		t.Fatal("first seal at counter 0 should not panic")
	}

	skipped := caught(func() { aead.Seal(nil, mkNonce(2), []byte("b"), nil) })
	if skipped {
		t.Fatal("counter 2 was rejected — bug appears patched")
	}

	t.Log("Sealed with counter 0 then counter 2; counter 1 was skipped without")
	t.Log("a panic. The deterministic-counter invariant requires consecutive")
	t.Log("increments, so this run violates the documented contract.")
}
