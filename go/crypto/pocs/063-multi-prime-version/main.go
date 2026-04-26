// PoC for finding 063: ParsePKCS1PrivateKey accepts a multi-prime RSA
// private key DER whose version field is 0 instead of 1.
//
// PKCS#1 mandates version == 1 whenever otherPrimeInfos is present, and
// MarshalPKCS1PrivateKey emits version = 1 in that case. The unpatched
// parser at src/crypto/x509/pkcs1.go:70 only rejects priv.Version > 1,
// so a 3-prime key with version=0 is wrongly accepted.
//
// We generate a 3-prime RSA key, marshal it, flip the version bytes from
// `02 01 01` (1) to `02 01 00` (0), and re-parse.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"os"
)

func main() {
	priv, err := rsa.GenerateMultiPrimeKey(rand.Reader, 3, 2048)
	if err != nil {
		panic(err)
	}
	if len(priv.Primes) != 3 {
		fmt.Println("expected 3 primes, got", len(priv.Primes))
		os.Exit(1)
	}
	der := x509.MarshalPKCS1PrivateKey(priv)

	// Marshal emits version=1 when len(Primes) > 2: `02 01 01` near the
	// start of the outer SEQUENCE.
	want := []byte{0x02, 0x01, 0x01}
	idx := bytes.Index(der, want)
	if idx < 0 {
		fmt.Println("could not locate version field with value 1")
		os.Exit(1)
	}
	tampered := bytes.Clone(der)
	tampered[idx+2] = 0x00 // version: 1 -> 0

	fmt.Printf("Original version: % x  (1 == multi-prime)\n", der[idx:idx+3])
	fmt.Printf("Tampered version: % x  (0 == two-prime, but 3 primes follow)\n", tampered[idx:idx+3])

	parsed, err := x509.ParsePKCS1PrivateKey(tampered)
	fmt.Println("EXPECTED: ParsePKCS1PrivateKey rejects version=0 with otherPrimeInfos")
	if err != nil {
		fmt.Println("GOT:      err =", err, "(bug did not reproduce)")
		os.Exit(2)
	}
	fmt.Println("GOT:      err == nil; primes =", len(parsed.Primes))
	fmt.Println("Validate:", parsed.Validate())
	fmt.Println("BUG REPRODUCED: 3-prime key accepted with PKCS#1 version=0.")
}
