// PoC for finding 046 — PublicKey.Bytes returns the internal validated
// public-key encoding. A caller can mutate the slice and corrupt the
// validated point, either making subsequent ECDH operations fail or causing
// them to compute against a different (still-valid) point than the one
// originally accepted.

package ecdh

import (
	"bytes"
	"testing"
)

func TestPoC046MutablePublicKey(t *testing.T) {
	c := P256()

	one := make([]byte, len(c.N))
	one[len(one)-1] = 1
	priv, err := NewPrivateKey(c, one)
	if err != nil {
		t.Fatalf("NewPrivateKey: %v", err)
	}
	pub := priv.PublicKey()

	originalPub := append([]byte(nil), pub.Bytes()...)

	exposed := pub.Bytes()
	for i := range exposed {
		exposed[i] ^= 0xff
	}

	mutated := pub.Bytes()
	if bytes.Equal(originalPub, mutated) {
		t.Fatalf("EXPECTED: Bytes() returns a defensive copy; GOT: caller cannot mutate internal q")
	}

	t.Logf("BUG REPRODUCED: caller mutated the validated public-key encoding through Bytes()")
	t.Logf("  q before: %x", originalPub)
	t.Logf("  q after : %x", mutated)

	peerScalar := make([]byte, len(c.N))
	peerScalar[len(peerScalar)-1] = 2
	peer, err := NewPrivateKey(c, peerScalar)
	if err != nil {
		t.Fatalf("peer NewPrivateKey: %v", err)
	}

	_, ecdhErr := ECDH(c, peer, pub)
	t.Logf("  peer ECDH against mutated public key: err=%v (mutation broke a previously-validated point)", ecdhErr)

	if ecdhErr == nil {
		t.Fatal("expected ECDH to fail against the mutated key")
	}
}
