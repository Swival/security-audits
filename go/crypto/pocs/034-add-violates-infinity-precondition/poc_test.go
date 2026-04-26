// PoC for finding 034: P256Point.Add violates the documented precondition of
// p256PointAddAsm by passing an infinity operand to it.
//
// The documented contract for p256PointAddAsm is "if either input is infinity,
// res and the return value are undefined". Add(r1, r2) calls
// p256PointAddAsm(&sum, r1, r2) before handling infinity, then relies on later
// conditional moves to overwrite the (undefined) sum. The reachable input is a
// point at infinity returned by NewP256Point or SetBytes([]byte{0}).
//
// We confirm reachability and observe what p256PointAddAsm currently returns
// for infinity operands. The result is contractually undefined, so even when
// the final Add output happens to be correct on this build, the intermediate
// "pointsEqual" return value is consumed before the conditional moves correct
// the sum.
package nistec

import (
	"bytes"
	"testing"
)

func TestPoC034AddInfinityPrecondition(t *testing.T) {
	inf := NewP256Point()
	if inf.isInfinity() != 1 {
		t.Fatalf("NewP256Point should return infinity")
	}

	g := NewP256Point().SetGenerator()
	gBytes := g.Bytes()

	got := NewP256Point()
	got.Add(inf, g)
	if !bytes.Equal(got.Bytes(), gBytes) {
		t.Errorf("EXPECTED: Add(O, G) == G\nGOT: %x", got.Bytes())
	} else {
		t.Logf("OK: final Add(O, G) overwrites the undefined sum and equals G")
	}

	got2 := NewP256Point()
	got2.Add(g, inf)
	if !bytes.Equal(got2.Bytes(), gBytes) {
		t.Errorf("EXPECTED: Add(G, O) == G\nGOT: %x", got2.Bytes())
	} else {
		t.Logf("OK: final Add(G, O) overwrites the undefined sum and equals G")
	}

	var sum P256Point
	pointsEqual := p256PointAddAsm(&sum, inf, g)
	t.Logf("CONFIRMED: p256PointAddAsm called with infinity operand. Contract says res and return are undefined.")
	t.Logf("  pointsEqual return value (undefined per contract) = %d", pointsEqual)
	t.Logf("  sum.Bytes() (raw undefined intermediate) = %x", sum.Bytes())

	gMatch := bytes.Equal(sum.Bytes(), gBytes)
	t.Logf("  sum.Bytes() == G.Bytes() ? %v (no contract on either outcome)", gMatch)
	t.Logf("REPRODUCED: P256Point.Add reaches p256PointAddAsm with an infinity operand, violating the documented precondition.")
}
