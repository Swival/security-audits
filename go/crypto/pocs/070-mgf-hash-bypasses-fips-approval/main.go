// PoC for finding 070: in FIPS 140-only mode, EncryptOAEPWithOptions enforces
// that the primary OAEP Hash is FIPS-approved but does not enforce the same
// requirement on the caller-supplied MGFHash. Because rsa/fips.go only checks
// `ApprovedHash(hash)` and not `ApprovedHash(mgfHash)`, the caller-controlled
// MGF1 hash reaches `mgf1XOR` without an approval check.
//
// The audit notes that SHA-1/MD5 panic from their own FIPS-only guards before
// this code path is reached, so this PoC takes the path the audit explicitly
// calls out: a hash registered through `crypto.RegisterHash`. We register a
// custom non-approved hash under the otherwise-unused `crypto.RIPEMD160`
// slot. It computes RIPEMD-160-style sized output by truncating SHA-256, but
// crucially it is not the internal *sha256.Digest type, so
// fips140only.ApprovedHash returns false for it.
//
// The program self-reexecs with GODEBUG=fips140=only.
//
// Run:
//
//	go run .
//
// Expected (patched): error "use of hash functions other than SHA-2 or SHA-3 is not allowed in FIPS 140-only mode".
// Actual (unpatched): EncryptOAEPWithOptions returns a ciphertext.
package main

import (
	"crypto"
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"hash"
	"os"
	"os/exec"
)

type fakeHash struct {
	hash.Hash
}

func (fakeHash) Size() int      { return 20 }
func (fakeHash) BlockSize() int { return 64 }
func (f fakeHash) Sum(b []byte) []byte {
	full := f.Hash.Sum(nil)
	return append(b, full[:20]...)
}

func newFake() hash.Hash { return fakeHash{Hash: sha256.New()} }

func init() {
	crypto.RegisterHash(crypto.RIPEMD160, newFake)
}

func main() {
	if os.Getenv("POC070_CHILD") != "1" {
		exe, err := os.Executable()
		if err != nil {
			fmt.Fprintln(os.Stderr, "executable:", err)
			os.Exit(2)
		}
		cmd := exec.Command(exe)
		cmd.Env = append(os.Environ(), "GODEBUG=fips140=only", "POC070_CHILD=1")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			os.Exit(1)
		}
		return
	}

	if !fips140.Enabled() {
		fmt.Println("SKIP: FIPS 140 not built into this Go toolchain")
		return
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("GenerateKey:", err)
		os.Exit(2)
	}

	opts := &rsa.OAEPOptions{
		Hash:    crypto.SHA256,
		MGFHash: crypto.RIPEMD160, // non-approved registered hash (custom)
	}
	msg := []byte("poc070")

	fmt.Printf("FIPS-only enforced:        %v\n", fips140.Enabled())
	fmt.Printf("OAEP hash:                 SHA-256 (approved)\n")
	fmt.Printf("MGF1 hash:                 RIPEMD160 slot, custom non-approved hash\n")

	ct, err := rsa.EncryptOAEPWithOptions(rand.Reader, &key.PublicKey, msg, opts)
	if err != nil {
		fmt.Printf("EncryptOAEPWithOptions:    error -> %v\n", err)
		fmt.Println("indicator: bug appears patched")
		return
	}
	fmt.Printf("EncryptOAEPWithOptions:    succeeded, %d byte ciphertext\n", len(ct))
	fmt.Println("BUG REPRODUCED: FIPS-only EncryptOAEPWithOptions accepted a non-approved MGF1 hash")
	os.Exit(1)
}
