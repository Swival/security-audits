// PoC for finding 075: in FIPS 140-only mode, rsa.SignPKCS1v15 (and
// VerifyPKCS1v15) panic when the caller passes hash == crypto.Hash(0).
//
// The API documents `hash == 0` as a legal value meaning "sign the input
// directly without prepending a DigestInfo." The non-FIPS branch handles this
// correctly. The FIPS-only branch unconditionally evaluates `hash.New()`
// before checking ApprovedHash, and `crypto.Hash(0).New()` panics because
// hash 0 has no registered constructor.
//
// The program self-reexecs with GODEBUG=fips140=only.
//
// Run:
//
//	go run .
//
// Expected (patched): standard error mentioning unapproved hash, no panic.
// Actual (unpatched): runtime panic "crypto: requested hash function #0 is unavailable".
package main

import (
	"crypto"
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"
	"os/exec"
	"runtime/debug"
)

func main() {
	if os.Getenv("POC075_CHILD") != "1" {
		exe, err := os.Executable()
		if err != nil {
			fmt.Fprintln(os.Stderr, "executable:", err)
			os.Exit(2)
		}
		cmd := exec.Command(exe)
		cmd.Env = append(os.Environ(), "GODEBUG=fips140=only", "POC075_CHILD=1")
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

	fmt.Printf("FIPS-only enforced:        %v\n", fips140.Enabled())
	fmt.Printf("hash:                      crypto.Hash(0)  (legal per SignPKCS1v15 docs)\n")

	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("BUG REPRODUCED: SignPKCS1v15 panicked: %v\n", r)
			fmt.Println("---- stack ----")
			os.Stderr.Write(debug.Stack())
			os.Exit(1)
		}
	}()

	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.Hash(0), []byte("poc075"))
	if err != nil {
		fmt.Printf("returned error (expected after patch): %v\n", err)
		fmt.Println("indicator: bug appears patched")
		return
	}
	fmt.Printf("unexpected success, signature len=%d\n", len(sig))
}
