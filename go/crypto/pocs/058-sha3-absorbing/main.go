// PoC for finding 058: SHA-3 UnmarshalBinary accepts the impossible
// "absorbing buffer is full" state (n == rate while still spongeAbsorbing).
//
// The marshaled wire format is:
//
//	magic(4) | rate(1) | state[200] | n(1) | direction(1)  -> 207 bytes
//
// For SHA3-256, rate = 136 and the absorbing direction is encoded as 0x00.
// We craft a blob with n = rate and state = absorbing (which the live update
// path would have permuted away by setting n back to 0). Sum() then runs
// padAndPermute, which writes d.dsbyte at d.a[d.n], i.e. d.a[136] of the
// 200-byte state -- legal memory but a SHA-3 sponge invariant violation.
//
// Evidence: a marshal->modify->unmarshal->Sum round-trip yields a digest
// for an impossible internal state instead of returning an error.
package main

import (
	"crypto/sha3"
	"encoding/hex"
	"fmt"
	"os"
)

func main() {
	const rate = 136 // SHA3-256 rate (200 - 2*32)
	h := sha3.New256()
	blob, err := h.MarshalBinary()
	if err != nil {
		fmt.Println("MarshalBinary failed:", err)
		os.Exit(2)
	}
	if len(blob) != 207 {
		fmt.Println("unexpected marshaled size:", len(blob))
		os.Exit(2)
	}

	// Layout: magic[0:4] | rate[4] | state[5:205] | n[205] | direction[206]
	if int(blob[4]) != rate {
		fmt.Println("unexpected rate byte:", blob[4])
		os.Exit(2)
	}

	blob[205] = byte(rate) // n = rate -> the impossible "buffer is full" state
	blob[206] = 0x00       // spongeAbsorbing

	h2 := sha3.New256()
	if err := h2.UnmarshalBinary(blob); err != nil {
		fmt.Println("EXPECTED a logical error from UnmarshalBinary on n==rate while absorbing")
		fmt.Println("GOT error:", err)
		fmt.Println("\n(this is the patched behaviour; bug not reproduced)")
		os.Exit(1)
	}
	fmt.Println("EXPECTED: UnmarshalBinary rejects state=spongeAbsorbing with n==rate")
	fmt.Println("GOT:      UnmarshalBinary accepted the impossible state")

	digest := h2.Sum(nil)
	fmt.Printf("Sum() over the impossible state returned a %d-byte digest:\n  %s\n",
		len(digest), hex.EncodeToString(digest))
	fmt.Println("\nBUG REPRODUCED: SHA-3 UnmarshalBinary lets callers create a sponge")
	fmt.Println("with a full absorbing buffer that the live Write path would never produce.")
}
