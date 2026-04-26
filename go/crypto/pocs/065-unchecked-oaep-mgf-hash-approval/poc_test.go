// PoC for finding 065: DecryptOAEP records the operation as FIPS-approved
// even when the caller-supplied MGF1 hash is not an approved hash.
//
// DecryptOAEP calls fips140.RecordApproved() and validates only the primary
// OAEP hash via checkApprovedHash. We feed an approved hash (SHA-256, the
// internal *sha256.Digest) and an unapproved MGF1 hash (stdlib SHA-1) into a
// valid OAEP roundtrip and observe ServiceIndicator() still reports approved
// after the decrypt.
//
// Run from inside the package directory:
//
//	cd /private/tmp/go/src/crypto/internal/fips140/rsa
//	go test -run TestPoC065 -v
package rsa

import (
	"crypto/internal/fips140"
	"crypto/internal/fips140/sha256"
	"crypto/rand"
	"crypto/sha1"
	"testing"
)

func TestPoC065DecryptOAEPMGFApprovalNotChecked(t *testing.T) {
	priv, err := GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub := priv.PublicKey()

	msg := []byte("poc065")

	ct, err := EncryptOAEP(sha256.New(), sha1.New(), rand.Reader, pub, msg, nil)
	if err != nil {
		t.Fatalf("EncryptOAEP: %v", err)
	}

	fips140.ResetServiceIndicator()
	pt, err := DecryptOAEP(sha256.New(), sha1.New(), priv, ct, nil)
	if err != nil {
		t.Fatalf("DecryptOAEP: %v", err)
	}
	approved := fips140.ServiceIndicator()
	t.Logf("OAEP roundtrip succeeded with %d bytes plaintext", len(pt))
	t.Logf("approved hash = SHA-256 (internal), MGF hash = SHA-1 (stdlib, non-approved)")
	t.Logf("ServiceIndicator after DecryptOAEP: %v", approved)

	if approved {
		t.Errorf("BUG REPRODUCED: DecryptOAEP reported approved=true with an unapproved MGF1 hash; expected approved=false")
		return
	}
	t.Log("indicator was downgraded; bug appears patched")
}
