// PoC for finding 025: PublicKey.Bytes() returns the internal q slice
// directly. A caller can mutate the returned slice and observe the change
// through later calls, even when the original Q input was not retained.
//
// This is distinct from finding 023, which exploits the alias to the original
// Q input. Here we use GenerateKey, which never exposes Q to the caller, and
// show that PublicKey.Bytes() still hands out a mutable alias to priv.pub.q.
package ecdsa

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestPoC025PublicKeyExposedMutably(t *testing.T) {
	c := P256()
	priv, err := GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub := priv.PublicKey()

	first := pub.Bytes()
	original := bytes.Clone(first)

	first[0] = 0
	first[1] = 0xFF

	second := pub.Bytes()
	if bytes.Equal(second, original) {
		t.Errorf("EXPECTED: returned slice aliases pub.q\nGOT: pub.Bytes() unchanged after mutation, no aliasing")
		return
	}
	t.Logf("CONFIRMED: pub.Bytes() returned slice aliases internal pub.q")
	t.Logf("original pub.Bytes()[0:3] = %x", original[:3])
	t.Logf("mutated  pub.Bytes()[0:3] = %x", second[:3])

	if second[0] != 0x00 {
		t.Errorf("expected mutated leading byte 0x00, got %#x", second[0])
		return
	}
	t.Logf("CONFIRMED: pub.q now begins with invalid encoding byte 0x00, which makes NewPublicKey reject the same key bytes")

	if _, err := NewPublicKey(c, pub.Bytes()); err == nil {
		t.Errorf("expected NewPublicKey to reject mutated bytes")
	} else {
		t.Logf("CONFIRMED: re-parsing pub.Bytes() now fails: %v", err)
	}
}
