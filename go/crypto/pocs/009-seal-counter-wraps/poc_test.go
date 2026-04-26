// PoC for finding 009 — HPKE Sender.Seal seqNum wraps past 2^64-1.
//
// Sender.Seal increments a uint64 sequence number after each successful
// encryption without any overflow check. If a Sender is exercised to
// math.MaxUint64 successful seals, the next post-increment wraps seqNum
// back to 0, and the subsequent Seal call derives the very same nonce
// the Sender used on its first ever call. Reaching 2^64 in real time is
// impractical, so this test reaches the precondition by reading a real
// Sender's first nonce, fast-forwarding seqNum to MaxUint64, performing
// one final Seal, and observing that seqNum is now 0 and the next nonce
// matches the saved first nonce. With the same AEAD key, that means the
// next Seal will reuse a nonce the Sender already used.
//
// This test reaches into the internal seqNum field through the test file's
// position inside crypto/hpke. Place this file at
// /private/tmp/go/src/crypto/hpke/poc009_test.go and run:
//
//   cd $(go env GOROOT)/src/crypto/hpke && go test -run TestPoC009 -v
//
// or against the unpatched tree once a 1.27 toolchain is available:
//
//   cd /private/tmp/go/src/crypto/hpke && go test -run TestPoC009 -v

package hpke

import (
	"bytes"
	"math"
	"testing"
)

func TestPoC009SealCounterWraps(t *testing.T) {
	kem, err := NewKEM(0x0020) // DHKEM(X25519, HKDF-SHA256)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := kem.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	_, sender, err := NewSender(priv.PublicKey(), HKDFSHA256(), AES128GCM(), nil)
	if err != nil {
		t.Fatal(err)
	}

	firstNonce := append([]byte(nil), sender.nextNonce()...)

	if _, err := sender.Seal(nil, []byte("first")); err != nil {
		t.Fatalf("first seal failed: %v", err)
	}

	if sender.seqNum != 1 {
		t.Fatalf("expected seqNum 1 after first seal, got %d", sender.seqNum)
	}

	sender.seqNum = math.MaxUint64

	preWrapNonce := append([]byte(nil), sender.nextNonce()...)

	if _, err := sender.Seal(nil, []byte("max")); err != nil {
		t.Fatalf("seal at MaxUint64 failed unexpectedly: %v", err)
	}

	if sender.seqNum != 0 {
		t.Fatalf("expected seqNum to wrap to 0, got %d", sender.seqNum)
	}

	postWrapNonce := append([]byte(nil), sender.nextNonce()...)

	t.Logf("first nonce        = %x", firstNonce)
	t.Logf("seqNum=MaxUint64   = %x", preWrapNonce)
	t.Logf("post-wrap nonce    = %x", postWrapNonce)

	if !bytes.Equal(firstNonce, postWrapNonce) {
		t.Fatalf("expected post-wrap nonce to equal first nonce, but they differ")
	}

	t.Log("MATCH: seqNum wrapped from MaxUint64 back to 0; the next Seal on this")
	t.Log("Sender will reuse the very first AEAD nonce under the same key.")
}
