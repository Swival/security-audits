// PoC for finding 042 — nil remote public key panics PrivateKey.ECDH.
//
// crypto/ecdh.PrivateKey.ECDH dereferences `remote.curve` before checking
// whether `remote` is nil. A caller passing a nil remote public key crashes
// the process with a runtime nil-pointer panic instead of getting a normal
// error return.
package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"os"
)

func main() {
	curve := ecdh.P256()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println("setup failed:", err)
		os.Exit(2)
	}

	defer func() {
		r := recover()
		if r == nil {
			fmt.Println("EXPECTED: panic from PrivateKey.ECDH(nil); GOT: no panic and no error")
			os.Exit(1)
		}
		fmt.Printf("PANIC AS EXPECTED: %v\n", r)
		fmt.Println()
		fmt.Println("Documented contract: ECDH returns (sharedSecret, error). A nil remote")
		fmt.Println("public key should be rejected with an error, not crash the process.")
	}()

	shared, err := priv.ECDH(nil)
	fmt.Printf("(unreachable) shared=%x err=%v\n", shared, err)
}
