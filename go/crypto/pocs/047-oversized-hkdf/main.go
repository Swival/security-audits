// PoC for finding 047 — TLS 1.3 ExportKeyingMaterial forwards the
// caller-controlled length into the internal fips140/hkdf.Expand without
// upper-bound validation. With SHA-256 the HKDF-Expand maximum is 255*32 ==
// 8160 bytes; requesting 8161 wraps the uint8 counter and triggers
// `panic("hkdf: counter overflow")` deep inside the cryptographic code path
// instead of returning a normal error from ExportKeyingMaterial.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"time"
)

func main() {
	cert, key := newCert()
	tlsCert, err := tls.X509KeyPair(cert, key)
	if err != nil {
		fmt.Println("X509KeyPair:", err)
		os.Exit(2)
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_AES_128_GCM_SHA256},
	})
	if err != nil {
		fmt.Println("Listen:", err)
		os.Exit(2)
	}
	defer listener.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		tlsConn := conn.(*tls.Conn)
		_ = tlsConn.Handshake()
		time.Sleep(200 * time.Millisecond)
		conn.Close()
	}()

	conn, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		CipherSuites:       []uint16{tls.TLS_AES_128_GCM_SHA256},
	})
	if err != nil {
		fmt.Println("Dial:", err)
		os.Exit(2)
	}
	defer conn.Close()

	if err := conn.Handshake(); err != nil {
		fmt.Println("Handshake:", err)
		os.Exit(2)
	}
	state := conn.ConnectionState()
	if state.Version != tls.VersionTLS13 {
		fmt.Println("not TLS 1.3, version:", state.Version)
		os.Exit(2)
	}

	const overLimit = 255*32 + 1

	defer func() {
		r := recover()
		if r == nil {
			fmt.Println("EXPECTED: panic or error from ExportKeyingMaterial(length=8161); GOT: no panic and no error returned")
			os.Exit(1)
		}
		fmt.Printf("PANIC AS EXPECTED: %v\n", r)
		fmt.Println()
		fmt.Println("Documented contract: ExportKeyingMaterial returns (km, error). RFC 5869")
		fmt.Println("requires HKDF outputs to be <= 255*HashLen bytes (here 8160 for SHA-256).")
		fmt.Printf("Requesting %d bytes should yield a clean error, not a counter-overflow panic.\n", overLimit)
	}()

	km, err := state.ExportKeyingMaterial("crypto/tls test", nil, overLimit)
	fmt.Printf("(unreachable) km len=%d err=%v\n", len(km), err)

	wg.Wait()
}

func newCert() (certPEM, keyPEM []byte) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "poc"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		panic(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		panic(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return
}
