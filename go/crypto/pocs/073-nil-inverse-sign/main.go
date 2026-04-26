// PoC for finding 073: nil kInv dereference in signLegacy.
//
// signLegacy computes kInv = ModInverse(k, N) without checking the result for
// nil. When N is composite, some nonces k satisfy gcd(k,N) > 1, so ModInverse
// returns nil. Execution then reaches s.Mul(s, kInv) and panics.
//
// We trigger this by providing a custom elliptic.Curve (reaching signLegacy)
// whose order N = 6. ScalarBaseMult always returns (1, 1) so r = 1 ≠ 0 and
// the inner retry loop breaks immediately regardless of k. With k ∈ {1…5},
// k ∈ {2, 3, 4} have gcd(k, 6) > 1, so on average the first call panics.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
)

type badCurve struct {
	params *elliptic.CurveParams
}

func (c *badCurve) Params() *elliptic.CurveParams { return c.params }
func (c *badCurve) ScalarBaseMult(_ []byte) (*big.Int, *big.Int) {
	return big.NewInt(1), big.NewInt(1)
}

func (c *badCurve) ScalarMult(_, _ *big.Int, _ []byte) (*big.Int, *big.Int) {
	return big.NewInt(1), big.NewInt(1)
}

func (c *badCurve) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	return new(big.Int).Add(x1, x2), new(big.Int).Add(y1, y2)
}

func (c *badCurve) Double(x, y *big.Int) (*big.Int, *big.Int) {
	return new(big.Int).Mul(big.NewInt(2), x), new(big.Int).Mul(big.NewInt(2), y)
}
func (c *badCurve) IsOnCurve(_, _ *big.Int) bool { return true }

func main() {
	curve := &badCurve{
		params: &elliptic.CurveParams{
			Name:    "bad-N6",
			P:       new(big.Int).Lsh(big.NewInt(1), 64),
			N:       big.NewInt(6), // composite: elements 2,3,4 are non-invertible
			B:       big.NewInt(3),
			Gx:      big.NewInt(1),
			Gy:      big.NewInt(1),
			BitSize: 64,
		},
	}

	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		fmt.Printf("GenerateKey: %v\n", err)
		return
	}
	fmt.Printf("key D = %d  (D mod 6 = %d)\n", priv.D, new(big.Int).Mod(priv.D, big.NewInt(6)))

	hash := []byte("hello world -- ECDSA nil kInv PoC")

	for i := 1; i <= 20; i++ {
		var panicked bool
		var panicVal any
		func() {
			defer func() {
				if r := recover(); r != nil {
					panicked = true
					panicVal = r
				}
			}()
			ecdsa.SignASN1(rand.Reader, priv, hash) //nolint:errcheck
		}()
		if panicked {
			fmt.Printf("attempt %d: PANIC AS EXPECTED: %v\n", i, panicVal)
			fmt.Println("REPRODUCED: signLegacy reaches s.Mul(s, nil) when kInv == nil for a non-invertible nonce mod composite N")
			return
		}
		fmt.Printf("attempt %d: no panic (invertible k this time)\n", i)
	}
	fmt.Println("no panic in 20 attempts — increase iteration count")
}
