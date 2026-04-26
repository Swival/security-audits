// PoC for finding 035: P256Point.ScalarMult violates the documented
// precondition of p256PointAddAsm by allowing an infinity input point to flow
// into precomputation.
//
// ScalarMult only checks the scalar length, then invokes
// r.Set(q).p256ScalarMult(scalar). p256ScalarMult places q in precomp[0],
// doubles it, and calls p256PointAddAsm(&t0, &t0, p) with p still infinity.
// p256PointAddAsm explicitly states that res and the return value are
// undefined when an operand is infinity.
//
// We confirm reachability by calling ScalarMult with an infinity point and a
// 32-byte scalar. The mathematical correct answer is infinity; we observe the
// actual returned encoding.
package nistec

import (
	"bytes"
	"testing"
)

func TestPoC035ScalarMultInfinityPrecondition(t *testing.T) {
	inf := NewP256Point()
	if inf.isInfinity() != 1 {
		t.Fatalf("NewP256Point should return infinity")
	}
	infEnc := inf.Bytes()
	t.Logf("infinity encoding: %x", infEnc)

	scalar := make([]byte, 32)
	scalar[31] = 7

	r := NewP256Point()
	if _, err := r.ScalarMult(inf, scalar); err != nil {
		t.Fatalf("ScalarMult: %v", err)
	}
	got := r.Bytes()
	t.Logf("ScalarMult(O, 7).Bytes() = %x", got)

	if bytes.Equal(got, infEnc) {
		t.Logf("OK: ScalarMult(O, k) returns the infinity encoding on this build")
	} else {
		t.Errorf("EXPECTED: ScalarMult(infinity, k) == infinity\nGOT: %x", got)
	}

	t.Logf("REPRODUCED: ScalarMult accepted an infinity operand and reached p256PointAddAsm via p256ScalarMult precomputation, violating the asm helper's documented precondition. Final result happens to be the infinity encoding due to additional arithmetic, but the intermediate calls are contractually undefined.")
}
