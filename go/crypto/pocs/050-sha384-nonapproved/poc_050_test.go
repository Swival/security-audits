// PoC for finding 050 — TLS 1.2 MasterSecret marks SHA-384 as non-approved.
//
// The switch on *sha512.Digest accepts size 46 or 64. Size 46 does not exist
// in the SHA-2 family — the constant is a typo for 48 (SHA-384's actual
// digest size). Therefore SHA-384 unconditionally records the FIPS service
// as non-approved, even though SP 800-135 explicitly allows SHA-384 here.

package tls12

import (
	"crypto/internal/fips140"
	"crypto/internal/fips140/sha512"
	"hash"
	"testing"
)

func TestPoC050SHA384MarkedNonApproved(t *testing.T) {
	h := sha512.New384()
	if h.Size() != 48 {
		t.Fatalf("SHA-384 size = %d, want 48", h.Size())
	}
	t.Logf("actual SHA-384 size: %d", h.Size())
	t.Logf("constant accepted in tls12.go: 46 (the bug), and 64 (SHA-512)")

	fips140.ResetServiceIndicator()

	pre := make([]byte, 48)
	transcript := make([]byte, 32)
	_ = MasterSecret(func() hash.Hash { return sha512.New384() }, pre, transcript)

	approved := fips140.ServiceIndicator()
	if approved {
		t.Fatal("expected SHA-384 to be flagged non-approved with the buggy constant; the bug may already be fixed")
	}
	t.Logf("BUG REPRODUCED: TLS 1.2 master secret derivation with SHA-384 reports approved=false because the size check uses 46 instead of 48")
}
