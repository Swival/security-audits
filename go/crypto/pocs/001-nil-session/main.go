// PoC for finding 001 — nil session inserted for missing key.
//
// crypto/tls.NewLRUClientSessionCache documents that a Put with a nil
// ClientSessionState should remove the entry. For an absent key, the LRU
// implementation falls through to the insert path and stores a nil entry.
// A subsequent Get(key) returns (nil, true), violating the documented
// contract.
package main

import (
	"crypto/tls"
	"fmt"
	"os"
)

func main() {
	cache := tls.NewLRUClientSessionCache(8)

	const key = "example.com:443"

	cache.Put(key, nil)

	state, ok := cache.Get(key)

	fmt.Printf("Put(%q, nil) on empty cache then Get -> state=%v ok=%v\n", key, state, ok)
	fmt.Println()
	fmt.Println("Documented contract: Put(key, nil) removes the entry, so Get must")
	fmt.Println("return (nil, false). Observed (nil, true) confirms the bug.")

	if ok {
		fmt.Println("\nBUG REPRODUCED: Get returned ok=true for a key that was never inserted.")
		os.Exit(0)
	}
	fmt.Println("\nUnexpected: bug did not reproduce.")
	os.Exit(1)
}
