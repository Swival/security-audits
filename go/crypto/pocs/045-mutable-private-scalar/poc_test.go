// PoC for finding 045 — PrivateKey.Bytes returns the internal validated
// scalar slice, letting callers mutate state that NewPrivateKey just
// validated (0 < d < n). After mutation the scalar can be zero or out of
// range and ECDH still consumes it without re-validating.

package ecdh

import (
	"bytes"
	"testing"
)

func TestPoC045MutablePrivateScalar(t *testing.T) {
	c := P256()

	one := make([]byte, len(c.N))
	one[len(one)-1] = 1
	priv, err := NewPrivateKey(c, one)
	if err != nil {
		t.Fatalf("NewPrivateKey: %v", err)
	}

	originalScalar := append([]byte(nil), priv.Bytes()...)

	exposed := priv.Bytes()
	for i := range exposed {
		exposed[i] = 0
	}

	if bytes.Equal(originalScalar, priv.Bytes()) {
		t.Fatalf("EXPECTED: Bytes() returns a defensive copy; GOT: caller cannot mutate internal scalar")
	}

	t.Logf("BUG REPRODUCED: caller mutated the validated private scalar through Bytes()")
	t.Logf("  scalar before mutation: %x", originalScalar)
	t.Logf("  scalar after  mutation: %x", priv.Bytes())

	twoBytes := make([]byte, len(c.N))
	twoBytes[len(twoBytes)-1] = 2
	peer, err := NewPrivateKey(c, twoBytes)
	if err != nil {
		t.Fatalf("peer NewPrivateKey: %v", err)
	}

	_, ecdhErr := ECDH(c, priv, peer.PublicKey())
	t.Logf("  ECDH with zeroed scalar: err=%v (should not be nil if zero would be rejected by validation)", ecdhErr)

	if isZero(priv.d) {
		t.Logf("  priv.d is now all zero, which NewPrivateKey would have rejected")
	}
}
