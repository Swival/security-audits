// PoC for finding 033 — FIPS GCMWithXORCounterNonce accepts skipped counters.
//
// crypto/internal/fips140/aes/gcm.GCMWithXORCounterNonce.Seal documents that
// each subsequent call must increment the counter by exactly one, but the
// pre-patch implementation only rejects counters strictly less than g.next.
// After Seal at counter 0, a Seal at counter 2 succeeds even though counter
// 1 was skipped, in violation of the deterministic-XOR-counter contract.
//
// Place this file at /private/tmp/go/src/crypto/cipher/ and run:
//
//   cd $(go env GOROOT)/src/crypto/cipher && \
//     GODEBUG=fips140=on go test -run TestPoC033 -v

package cipher_test

import (
	"crypto/internal/fips140"
	fipsaes "crypto/internal/fips140/aes"
	"crypto/internal/fips140/aes/gcm"
	"encoding/binary"
	"testing"
)

func TestPoC033XORCounterNonceSkip(t *testing.T) {
	if !fips140.Enabled {
		t.Skip("FIPS mode required: re-run with GODEBUG=fips140=on")
	}

	key := make([]byte, 16)
	block, err := fipsaes.New(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := gcm.NewGCMWithXORCounterNonce(block)
	if err != nil {
		t.Fatal(err)
	}

	mkNonce := func(counter uint64) []byte {
		n := make([]byte, 12)
		copy(n, []byte("xPoC"))
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

	t.Log("Sealed with XOR-counter 0 then XOR-counter 2; counter 1 was skipped")
	t.Log("without a panic. The deterministic XOR-counter invariant requires")
	t.Log("consecutive increments, so this run violates the documented contract.")
}
