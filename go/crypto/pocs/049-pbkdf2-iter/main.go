// PoC for finding 049: PBKDF2 accepts non-positive iteration counts.
//
// Evidence: with iter <= 0, crypto/pbkdf2.Key returns key material instead
// of an error. The output for iter=0 (and iter=-5) matches iter=1, proving
// the iteration loop was simply skipped instead of rejecting bad input.
package main

import (
	"bytes"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
)

func main() {
	password := "hunter2"
	salt := []byte("0123456789abcdef")

	failed := false

	for _, iter := range []int{0, -1, -1000} {
		out, err := pbkdf2.Key(sha256.New, password, salt, iter, 32)
		if err != nil {
			fmt.Printf("iter=%d: rejected with error %q (this is the patched behaviour)\n", iter, err)
			continue
		}
		fmt.Printf("iter=%d: EXPECTED an error; GOT %d bytes of key %s\n", iter, len(out), hex.EncodeToString(out))
		failed = true
	}

	one, err := pbkdf2.Key(sha256.New, password, salt, 1, 32)
	if err != nil {
		fmt.Printf("iter=1 baseline failed: %v\n", err)
		os.Exit(2)
	}
	zero, err := pbkdf2.Key(sha256.New, password, salt, 0, 32)
	if err == nil {
		if bytes.Equal(one, zero) {
			fmt.Println("\niter=0 output equals iter=1 output: the loop `for n := 2; n <= iter; n++`")
			fmt.Println("is simply skipped, so PBKDF2 collapses to a single PRF call.")
			fmt.Printf("iter=0 -> %s\n", hex.EncodeToString(zero))
			fmt.Printf("iter=1 -> %s\n", hex.EncodeToString(one))
		}
	}

	if failed {
		fmt.Println("\nBUG REPRODUCED: pbkdf2.Key silently accepts non-positive iteration counts.")
		os.Exit(0)
	}
	fmt.Println("\nbug not reproduced (build appears patched).")
	os.Exit(1)
}
