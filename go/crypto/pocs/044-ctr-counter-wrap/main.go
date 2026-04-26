// PoC for finding 044 — AES-CTR 128-bit counter wrap is unchecked.
//
// crypto/internal/fips140/aes (used by crypto/cipher.NewCTR through the
// generic cipher.Stream wrapper) advances the CTR counter using add128
// without checking the carry out of the high limb. When the IV is close
// to 2^128 - 1 and enough keystream is requested, the counter silently
// wraps to a value the caller could also produce with a low IV. Two
// streams encrypted under the same key end up sharing keystream blocks.
//
// Reproduction outline:
//   - Encrypt 32 zero bytes with key=0, IV=0xff..ff. The first block
//     uses counter 0xff..ff; the second wraps to 0.
//   - Encrypt 16 zero bytes with the same key and IV=0x00..00. That
//     block uses counter 0.
//   - The wrapped block from the first stream equals the only block of
//     the second stream, exposing keystream reuse.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"os"
)

func encrypt(key, iv, plaintext []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	ct := make([]byte, len(plaintext))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ct, plaintext)
	return ct
}

func main() {
	key := make([]byte, 16)

	highIV := make([]byte, aes.BlockSize)
	for i := range highIV {
		highIV[i] = 0xff
	}
	lowIV := make([]byte, aes.BlockSize)

	highPT := make([]byte, 32)
	highCT := encrypt(key, highIV, highPT)

	lowPT := make([]byte, 16)
	lowCT := encrypt(key, lowIV, lowPT)

	wrappedBlock := highCT[16:32]
	freshBlock := lowCT

	fmt.Printf("ciphertext A (IV=0xff..ff, 32 bytes): %s\n", hex.EncodeToString(highCT))
	fmt.Printf("  block 0 (counter 0xff..ff):        %s\n", hex.EncodeToString(highCT[:16]))
	fmt.Printf("  block 1 (counter wraps to 0):      %s\n", hex.EncodeToString(wrappedBlock))
	fmt.Printf("ciphertext B (IV=0x00..00, 16 bytes): %s\n", hex.EncodeToString(freshBlock))

	if string(wrappedBlock) == string(freshBlock) {
		fmt.Println("\nMATCH: wrapped-counter keystream equals counter-0 keystream.")
		fmt.Println("AES-CTR silently reused keystream across two distinct calls under")
		fmt.Println("the same key. Confidentiality of CTR mode is broken.")
		os.Exit(0)
	}

	fmt.Println("\nNo match — counter wrap was rejected (bug not present).")
	os.Exit(1)
}
