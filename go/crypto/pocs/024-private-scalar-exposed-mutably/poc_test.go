// PoC for finding 024: PrivateKey.Bytes() returns the internal scalar slice
// directly, so a caller can mutate the private scalar after construction.
//
// PrivateKey.Bytes() is documented to return the private scalar as a byte
// slice. Returning the backing array allows external code to overwrite
// priv.d, changing the signing scalar without altering the stored public
// key. This breaks key immutability for the FIPS 140 internal ECDSA type.
package ecdsa

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestPoC024PrivateScalarExposedMutably(t *testing.T) {
	c := P256()
	priv, err := GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	first := priv.Bytes()
	originalScalar := bytes.Clone(first)

	for i := range first {
		first[i] = 0xAA
	}

	second := priv.Bytes()
	if bytes.Equal(second, originalScalar) {
		t.Errorf("EXPECTED: returned slice aliases priv.d\nGOT: priv.Bytes() unchanged after mutation, no aliasing")
	} else {
		t.Logf("CONFIRMED: priv.Bytes() returned slice aliases internal priv.d")
		t.Logf("original priv.Bytes() prefix: %x", originalScalar[:8])
		t.Logf("after mutation prefix:        %x", second[:8])
	}

	if !bytes.Equal(second, bytes.Repeat([]byte{0xAA}, len(second))) {
		t.Errorf("priv.d was not fully overwritten as expected")
	} else {
		t.Logf("CONFIRMED: priv.d is now completely attacker-controlled bytes (0xAA...)")
	}
}
