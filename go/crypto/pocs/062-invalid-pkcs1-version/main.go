// PoC for finding 062: ParsePKCS1PrivateKey accepts a PKCS#1 RSA private
// key DER whose ASN.1 version INTEGER is negative (e.g. -1).
//
// The unpatched src/crypto/x509/pkcs1.go:70 reads:
//
//	if priv.Version > 1 {
//	    return nil, errors.New("x509: unsupported private key version")
//	}
//
// Because -1 is not greater than 1, a negative version slips through and
// the rest of the structure is accepted as a valid RSA private key.
//
// We marshal a valid 2-prime RSA private key (version 0 = `02 01 00`) and
// flip the version bytes to `02 01 ff` (DER for -1).
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
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	der := x509.MarshalPKCS1PrivateKey(priv)

	// Find the leading version field "02 01 00" inside the outer SEQUENCE
	// and replace its value byte with 0xff (DER -1). PKCS#1 version is the
	// first INTEGER in the SEQUENCE.
	want := []byte{0x02, 0x01, 0x00}
	idx := bytes.Index(der, want)
	if idx < 0 {
		fmt.Println("could not locate version field")
		os.Exit(1)
	}
	tampered := bytes.Clone(der)
	tampered[idx+2] = 0xff // version: 0 -> -1

	fmt.Printf("Original version DER bytes: % x\n", der[idx:idx+3])
	fmt.Printf("Tampered version DER bytes: % x\n", tampered[idx:idx+3])

	parsed, err := x509.ParsePKCS1PrivateKey(tampered)
	fmt.Println("EXPECTED: ParsePKCS1PrivateKey rejects negative version")
	if err != nil {
		fmt.Println("GOT:      err =", err, "(bug did not reproduce)")
		os.Exit(2)
	}
	fmt.Println("GOT:      err == nil; key recovered with bits =", parsed.N.BitLen())
	fmt.Println("Validate:", parsed.Validate())
	fmt.Println("BUG REPRODUCED: PKCS#1 private key with version=-1 accepted.")
}
