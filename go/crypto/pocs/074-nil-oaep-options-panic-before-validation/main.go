// PoC for finding 074: rsa.EncryptOAEPWithOptions panics on a nil
// *OAEPOptions argument. The first line of the function dereferences
// `opts.MGFHash` without a nil guard. Other nil-options paths in the same
// package (e.g. PSSOptions.saltLength) handle nil gracefully, so this is a
// missing input check, not intentional behavior.
//
// Run:
//
//	go run .
//
// Expected (patched): error like "crypto/rsa: missing OAEPOptions".
// Actual (unpatched): runtime panic with "invalid memory address or nil
// pointer dereference" inside EncryptOAEPWithOptions.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"
	"runtime/debug"
)

func main() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("GenerateKey:", err)
		os.Exit(2)
	}

	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("BUG REPRODUCED: EncryptOAEPWithOptions(nil opts) panicked: %v\n", r)
			fmt.Println("---- stack ----")
			os.Stderr.Write(debug.Stack())
			os.Exit(1)
		}
	}()

	ct, err := rsa.EncryptOAEPWithOptions(rand.Reader, &key.PublicKey, []byte("poc074"), nil)
	if err != nil {
		fmt.Printf("returned error (expected after patch): %v\n", err)
		fmt.Println("indicator: bug appears patched")
		return
	}
	fmt.Printf("unexpected success, ciphertext len=%d\n", len(ct))
}
