// PoC for finding 060: ParseCertificate accepts a policyConstraints
// extension whose requireExplicitPolicy ([0] IMPLICIT INTEGER) is encoded
// as a negative ASN.1 INTEGER (e.g. -1).
//
// RFC 5280 defines requireExplicitPolicy as SkipCerts ::= INTEGER (0..MAX),
// so negative values are invalid. The unpatched parser at
// src/crypto/x509/parser.go:763-773 only checks for integer overflow, not
// for negative values. The decoded -1 lands in Certificate.RequireExplicitPolicy.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"os"
	"time"
)

func main() {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)

	// policyConstraints SEQUENCE { [0] IMPLICIT -1 } = 30 03 80 01 ff
	pcVal := []byte{0x30, 0x03, 0x80, 0x01, 0xff}

	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "poc-060"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		ExtraExtensions: []pkix.Extension{
			{
				Id:       asn1.ObjectIdentifier{2, 5, 29, 36},
				Critical: false,
				Value:    pcVal,
			},
		},
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		fmt.Println("CreateCertificate:", err)
		os.Exit(1)
	}

	parsed, err := x509.ParseCertificate(der)
	fmt.Println("policyConstraints DER:", fmt.Sprintf("% x", pcVal))
	fmt.Println("EXPECTED: ParseCertificate rejects negative requireExplicitPolicy")
	if err != nil {
		fmt.Println("GOT:      err =", err, "(bug did not reproduce)")
		os.Exit(2)
	}
	fmt.Println("GOT:      err == nil")
	fmt.Println("RequireExplicitPolicy:", parsed.RequireExplicitPolicy)
	fmt.Println("RequireExplicitPolicyZero:", parsed.RequireExplicitPolicyZero)
	fmt.Println("BUG REPRODUCED: negative requireExplicitPolicy parsed and stored.")
}
