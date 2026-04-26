// PoC for finding 039: ParseECPrivateKey accepts trailing DER bytes.
//
// The unpatched parseECPrivateKey at src/crypto/x509/sec1.go:87 calls
// asn1.Unmarshal but discards the returned `rest` slice. Appending an
// extra DER object (or any bytes) to a valid SEC 1 EC PRIVATE KEY blob
// is silently accepted.
//
// This PoC marshals a real EC key, appends DER NULL (0x05 0x00), and
// re-parses. Output proves that ParseECPrivateKey returns nil error and
// the same private scalar.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"os"
)

func main() {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		panic(err)
	}

	// Append a DER NULL (0x05 0x00) — extra bytes outside the SEC 1 SEQUENCE.
	tampered := append(bytes.Clone(der), 0x05, 0x00)

	parsed, err := x509.ParseECPrivateKey(tampered)
	fmt.Printf("Original DER length:        %d\n", len(der))
	fmt.Printf("Tampered DER length:        %d (appended 0x05 0x00)\n", len(tampered))
	fmt.Println("EXPECTED: ParseECPrivateKey rejects trailing data")
	if err != nil {
		fmt.Println("GOT:      err =", err, "(bug did not reproduce)")
		os.Exit(2)
	}
	fmt.Println("GOT:      err == nil")
	fmt.Println("Same scalar:", parsed.D.Cmp(priv.D) == 0)
	fmt.Println("BUG REPRODUCED: trailing DER bytes silently ignored.")
}
