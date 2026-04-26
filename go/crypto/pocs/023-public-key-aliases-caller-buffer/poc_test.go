// PoC for finding 023: NewPublicKey aliases the caller-provided Q slice.
//
// crypto/internal/fips140/ecdsa.NewPublicKey validates Q with SetBytes, but
// stores the original slice in PublicKey.q. After construction, the caller can
// mutate the original slice and observe the change through PublicKey.Bytes(),
// breaking key immutability and influencing later verification.
package ecdsa

import (
	"bytes"
	"crypto/internal/fips140/nistec"
	"testing"
)

func TestPoC023PublicKeyAliasesCallerBuffer(t *testing.T) {
	c := P256()
	g, err := nistec.NewP256Point().ScalarBaseMult(append(make([]byte, 31), 1))
	if err != nil {
		t.Fatalf("ScalarBaseMult: %v", err)
	}
	Q := g.Bytes()
	original := bytes.Clone(Q)

	pub, err := NewPublicKey(c, Q)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}

	if !bytes.Equal(pub.Bytes(), original) {
		t.Fatalf("pub.Bytes() mismatch before mutation")
	}

	Q[0] = 0
	Q[1] = 0
	Q[2] = 0

	got := pub.Bytes()
	if bytes.Equal(got, original) {
		t.Errorf("EXPECTED: pub.Bytes() to alias caller buffer\nGOT: pub.Bytes() unchanged after mutating caller's Q")
	} else {
		t.Logf("CONFIRMED: caller-side mutation observable through pub.Bytes()")
		t.Logf("original Q[0:3] = %x", original[:3])
		t.Logf("mutated  Q[0:3] = %x", got[:3])
	}

	if got[0] == 0 {
		t.Logf("CONFIRMED: pub.q now starts with invalid encoding byte 0x00")
	}
}
