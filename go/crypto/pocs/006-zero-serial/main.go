// PoC for finding 006: zero certificate serial accepted by CreateCertificate.
//
// RFC 5280 Section 4.1.2.2 mandates that certificate serial numbers be a
// positive integer. The unpatched validation in crypto/x509.CreateCertificate
// is `serialNumber.Sign() == -1`, which only rejects negative values. A
// SerialNumber of zero passes the check and produces an RFC-invalid cert.
//
// Output proves: CreateCertificate returns a non-nil cert with err == nil
// when the template's SerialNumber is big.NewInt(0).
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"time"
)

func main() {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("keygen:", err)
		os.Exit(1)
	}

	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(0), // <-- bug: zero serial
		Subject:      pkix.Name{CommonName: "poc-006"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		fmt.Println("EXPECTED: error rejecting zero serial; GOT err:", err)
		os.Exit(2)
	}

	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		fmt.Println("ParseCertificate:", err)
		os.Exit(3)
	}

	fmt.Println("EXPECTED: CreateCertificate rejects zero serial (err non-nil)")
	fmt.Println("GOT:      err == nil; certificate produced with serial =", parsed.SerialNumber)
	fmt.Println("Sign() of serial:", parsed.SerialNumber.Sign())
	fmt.Println("DER length:", len(der))
}
