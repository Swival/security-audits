// PoC for finding 021: ExpShortVarTime returns base instead of 1 for e == 0.
//
// Mathematical correctness requires x^0 mod m == 1 mod m for any base x and
// odd modulus m > 1. The unpatched implementation skips its
// square-and-multiply loop when e == 0 and falls through to a Montgomery
// reduction of the input, returning x mod m.
//
// Run from inside the package directory:
//
//	cd /private/tmp/go/src/crypto/internal/fips140/bigmod
//	go test -run TestPoC021 -v
//
// Source location of installed copy:
//
//	/private/tmp/go/src/crypto/internal/fips140/bigmod/poc_test.go
package bigmod

import (
	"bytes"
	"testing"
)

func TestPoC021ExpShortVarTimeZeroExponent(t *testing.T) {
	// m = 5 (odd, > 1), x = 3, e = 0.
	m, err := NewModulus([]byte{5})
	if err != nil {
		t.Fatalf("NewModulus: %v", err)
	}

	x := NewNat()
	if _, err := x.SetBytes([]byte{3}, m); err != nil {
		t.Fatalf("SetBytes: %v", err)
	}

	out := NewNat()
	out.ExpShortVarTime(x, 0, m)

	got := out.Bytes(m)

	want := make([]byte, len(got))
	want[len(want)-1] = 1

	t.Logf("3^0 mod 5: got=%x want=%x", got, want)
	if !bytes.Equal(got, want) {
		t.Errorf("ExpShortVarTime(3, 0, 5) = %x, want %x (i.e. 1 mod m)", got, want)
		return
	}
	t.Errorf("ExpShortVarTime returned 1, bug appears patched")
}
