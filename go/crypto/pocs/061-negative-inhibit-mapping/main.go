// PoC for finding 061: ParseCertificate accepts a policyConstraints
// extension whose inhibitPolicyMapping ([1] IMPLICIT INTEGER) is encoded
// as a negative ASN.1 INTEGER.
//
// inhibitPolicyMapping is SkipCerts ::= INTEGER (0..MAX). The unpatched
// parser at src/crypto/x509/parser.go:775-786 only checks integer overflow,
// not negativity. A DER-encoded -1 is stored in Certificate.InhibitPolicyMapping.
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

	// policyConstraints SEQUENCE { [1] IMPLICIT -1 } = 30 03 81 01 ff
	pcVal := []byte{0x30, 0x03, 0x81, 0x01, 0xff}

	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "poc-061"},
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
	fmt.Println("EXPECTED: ParseCertificate rejects negative inhibitPolicyMapping")
	if err != nil {
		fmt.Println("GOT:      err =", err, "(bug did not reproduce)")
		os.Exit(2)
	}
	fmt.Println("GOT:      err == nil")
	fmt.Println("InhibitPolicyMapping:", parsed.InhibitPolicyMapping)
	fmt.Println("InhibitPolicyMappingZero:", parsed.InhibitPolicyMappingZero)
	fmt.Println("BUG REPRODUCED: negative inhibitPolicyMapping parsed and stored.")
}
