// PoC for finding 064: EncryptOAEP records the operation as FIPS-approved
// even when the caller-supplied MGF1 hash is not an approved hash.
//
// The internal EncryptOAEP function calls fips140.RecordApproved() and runs
// checkApprovedHash on the OAEP hash but never on the MGF1 hash. We pass an
// approved primary hash (SHA-256) and a non-approved MGF1 hash (SHA-1, from
// the standard library, which is not one of the internal *sha256.Digest /
// *sha512.Digest / *sha3.Digest types accepted by checkApprovedHash) and
// observe that ServiceIndicator() still reports approved.
//
// Run from inside the package directory:
//
//	cd /private/tmp/go/src/crypto/internal/fips140/rsa
//	go test -run TestPoC064 -v
package rsa

import (
	"crypto/internal/fips140"
	"crypto/internal/fips140/sha256"
	"crypto/rand"
	"crypto/sha1"
	"testing"
)

func TestPoC064EncryptOAEPMGFApprovalNotChecked(t *testing.T) {
	priv, err := GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub := priv.PublicKey()

	approvedHash := sha256.New()
	nonApprovedMGF := sha1.New()

	msg := []byte("poc064")

	fips140.ResetServiceIndicator()
	if _, err := EncryptOAEP(approvedHash, nonApprovedMGF, rand.Reader, pub, msg, nil); err != nil {
		t.Fatalf("EncryptOAEP: %v", err)
	}
	approved := fips140.ServiceIndicator()
	t.Logf("approved hash = SHA-256 (internal), MGF hash = SHA-1 (stdlib, non-approved)")
	t.Logf("ServiceIndicator after EncryptOAEP: %v", approved)

	if approved {
		t.Errorf("BUG REPRODUCED: EncryptOAEP reported approved=true with an unapproved MGF1 hash; expected approved=false")
		return
	}
	t.Log("indicator was downgraded; bug appears patched")
}
