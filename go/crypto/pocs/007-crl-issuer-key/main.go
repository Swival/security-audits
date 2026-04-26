// PoC for finding 007: CreateRevocationList does not enforce that the
// signing private key matches the issuer certificate's public key.
//
// The unpatched code derives the CRL Issuer DN and AuthorityKeyId from the
// issuer certificate, then signs the TBSCertList with whatever private key
// was passed in. There is no priv.Public() == issuer.PublicKey check.
//
// Output proves: CreateRevocationList accepts mismatched issuer/signer pair
// and produces a CRL whose declared issuer cannot verify the signature
// (CheckSignatureFrom fails on the resulting CRL).
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

func makeIssuer(cn string) (*x509.Certificate, *rsa.PrivateKey) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{1, 2, 3, 4},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return cert, priv
}

func main() {
	declaredIssuer, _ := makeIssuer("declared-issuer")
	_, attackerKey := makeIssuer("attacker")

	tpl := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Hour),
		NextUpdate: time.Now().Add(24 * time.Hour),
	}

	// Sign with attackerKey while declaring declaredIssuer as issuer.
	crlDER, err := x509.CreateRevocationList(rand.Reader, tpl, declaredIssuer, attackerKey)
	if err != nil {
		fmt.Println("EXPECTED: error rejecting key mismatch; GOT err:", err)
		os.Exit(2)
	}

	parsed, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		fmt.Println("parse CRL:", err)
		os.Exit(3)
	}

	fmt.Println("EXPECTED: CreateRevocationList rejects mismatched priv/issuer key")
	fmt.Println("GOT:      err == nil; CRL emitted with",
		"len(DER)=", len(crlDER))

	// Demonstrate the CRL is internally inconsistent: declared issuer cannot
	// verify the signature.
	verifyErr := parsed.CheckSignatureFrom(declaredIssuer)
	fmt.Println("CheckSignatureFrom(declaredIssuer):", verifyErr)
	if verifyErr == nil {
		fmt.Println("UNEXPECTED: signature verified")
		os.Exit(4)
	}
	fmt.Println("Bug confirmed: CRL declares issuer A but is signed by key B.")
}
