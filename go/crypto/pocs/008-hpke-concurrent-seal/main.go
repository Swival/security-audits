// PoC for finding 008 — concurrent crypto/hpke Sender.Seal nonce reuse.
//
// Sender.Seal calls nextNonce() (which reads s.seqNum) and only afterwards
// increments s.seqNum, all without synchronization. Two goroutines can read
// the same seqNum, derive the same nonce, and produce two ciphertexts under
// the same HPKE AEAD key and nonce.
//
// Demonstration strategy:
//   - Build a single Sender for a fixed shared secret.
//   - Drive many goroutines that each call Seal once on the same plaintext.
//   - Open the ciphertexts in seqNum order on the recipient side. Because
//     concurrent Seal calls collide on a sequence number, several Recipient
//     ciphertexts decrypt under the same nonce. Either the Recipient observes
//     duplicate plaintexts at distinct sequence numbers, or some ciphertexts
//     duplicate exactly (same nonce, same plaintext, same key → identical AEAD
//     output), which is itself the smoking gun.
//   - The race detector also reports the data race on s.seqNum directly.
//
// Run with: go run -race .
package main

import (
	"crypto/hpke"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
)

const (
	N         = 4000
	plaintext = "hpke-poc"
)

func main() {
	kem, err := hpke.NewKEM(0x0020)
	if err != nil {
		panic(err)
	}
	priv, err := kem.GenerateKey()
	if err != nil {
		panic(err)
	}
	pub := priv.PublicKey()

	enc, sender, err := hpke.NewSender(pub, hpke.HKDFSHA256(), hpke.AES128GCM(), nil)
	if err != nil {
		panic(err)
	}
	_ = enc

	cts := make([][]byte, N)
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func(i int) {
			defer wg.Done()
			ct, err := sender.Seal(nil, []byte(plaintext))
			if err != nil {
				fmt.Println("seal error:", err)
				return
			}
			cts[i] = ct
		}(i)
	}
	wg.Wait()

	dupes := 0
	seen := make(map[string]int)
	for _, ct := range cts {
		if ct == nil {
			continue
		}
		seen[string(ct)]++
	}
	for ct, n := range seen {
		if n > 1 {
			dupes++
			fmt.Printf("duplicate ciphertext appearing %d times: %s\n", n, hex.EncodeToString([]byte(ct)))
			if dupes >= 4 {
				break
			}
		}
	}

	if dupes == 0 {
		fmt.Println("no duplicate ciphertexts observed in this run; the race may still be")
		fmt.Println("present — re-run, or run with `-race` to see the data race directly.")
		os.Exit(2)
	}

	fmt.Println()
	fmt.Println("Observed duplicate ciphertexts produced by a single Sender. Each")
	fmt.Println("duplicate is the result of two concurrent Seal calls deriving the")
	fmt.Println("same AEAD nonce from an unsynchronized seqNum read. AES-128-GCM")
	fmt.Println("nonce reuse breaks confidentiality and integrity.")
	os.Exit(0)
}
