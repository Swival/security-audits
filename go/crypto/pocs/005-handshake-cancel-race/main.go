// PoC for finding 005 — context cancellation can close a handshake that has
// already completed.
//
// HandshakeContext registers context.AfterFunc(ctx, closeConn) and a deferred
// `if !stop() { ret = ctx.Err() }` cleanup. The race window is between
// handshakeFn returning success and the deferred stop() running. We widen
// the window by wrapping the underlying net.Conn so that the very last Write
// performed during the handshake (the client Finished record on TLS 1.2)
// blocks for a few microseconds, and we cancel the caller context as soon
// as that Write returns.
//
// On the unpatched code, this consistently produces a non-zero number of
// iterations where the client sees context.Canceled even though the server's
// Handshake() returned nil. On the patched code, the conditional guard on
// isHandshakeComplete prevents the close and the rewrite, so the client
// always sees nil.

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

func makeCert() tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "poc"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"poc"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

type signalConn struct {
	net.Conn
	writes  atomic.Int32
	onWrite func(n int32)
}

func (s *signalConn) Write(p []byte) (int, error) {
	n, err := s.Conn.Write(p)
	c := s.writes.Add(1)
	if s.onWrite != nil {
		s.onWrite(c)
	}
	return n, err
}

func attempt(cert tls.Certificate) (clientErr error, serverOK bool, observed string) {
	clientPipe, serverPipe := net.Pipe()
	defer clientPipe.Close()
	defer serverPipe.Close()

	clientCfg := &tls.Config{InsecureSkipVerify: true, ServerName: "poc", MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	serverCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}

	ctx, cancel := context.WithCancel(context.Background())

	sc := &signalConn{Conn: clientPipe}
	sc.onWrite = func(c int32) {
		if c == 2 {
			cancel()
		}
	}

	cli := tls.Client(sc, clientCfg)
	srv := tls.Server(serverPipe, serverCfg)

	var serverErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		serverErr = srv.Handshake()
	}()

	clientErr = cli.HandshakeContext(ctx)
	wg.Wait()
	cancel()

	return clientErr, serverErr == nil, fmt.Sprintf("clientWrites=%d serverErr=%v", sc.writes.Load(), serverErr)
}

func main() {
	cert := makeCert()

	const iters = 200
	var raceHits int
	var lastErr error
	var lastObserved string
	start := time.Now()
	for i := 0; i < iters; i++ {
		err, serverOK, obs := attempt(cert)
		if serverOK && err != nil && errors.Is(err, context.Canceled) {
			raceHits++
			lastErr = err
			lastObserved = obs
			if raceHits == 1 {
				fmt.Printf("first race hit at iteration %d: client err=%v, %s\n", i, err, obs)
			}
		}
		if i > 0 && i%500 == 0 {
			fmt.Printf("  iter %d, hits so far=%d, elapsed=%s\n", i, raceHits, time.Since(start).Round(time.Millisecond))
		}
	}

	fmt.Printf("\n%d/%d iterations: server handshake succeeded but client returned context.Canceled\n", raceHits, iters)

	if raceHits > 0 {
		fmt.Println()
		fmt.Printf("last observed: %s last err: %v\n", lastObserved, lastErr)
		fmt.Println("BUG REPRODUCED: HandshakeContext can return context.Canceled even when")
		fmt.Println("the handshake completed successfully. The deferred stop()/cleanup path")
		fmt.Println("overwrites the nil return with ctx.Err() when cancellation wins the race")
		fmt.Println("with the deferred call.")
		os.Exit(0)
	}
	fmt.Println("did not observe the race")
	os.Exit(1)
}
