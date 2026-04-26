// PoC for finding 048 — crypto/hkdf.Key forwards a caller-supplied negative
// keyLength into the internal hkdf.Expand without rejecting it. The
// internal Expand allocates `make([]byte, 0, keyLen)` before validating
// the length, triggering a Go runtime panic ("makeslice: cap out of range")
// instead of a normal returned error.
package main

import (
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
	"os"
)

func main() {
	defer func() {
		r := recover()
		if r == nil {
			fmt.Println("EXPECTED: panic from hkdf.Key(length=-1); GOT: no panic and no error returned")
			os.Exit(1)
		}
		fmt.Printf("PANIC AS EXPECTED: %v\n", r)
		fmt.Println()
		fmt.Println("Documented contract: hkdf.Key returns (key, error). A negative keyLength")
		fmt.Println("should be rejected with an error, not crash the process via makeslice.")
	}()

	secret := make([]byte, 32)
	out, err := hkdf.Key(sha256.New, secret, nil, "ctx", -1)
	fmt.Printf("(unreachable) out=%v err=%v\n", out, err)
}
