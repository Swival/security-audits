# ScalarMult Violates Infinity Precondition

## Classification

Invariant violation, medium severity. Confidence: certain.

## Affected Locations

`src/crypto/internal/fips140/nistec/p256_asm.go:679`

## Summary

`ScalarMult` accepts an input point at infinity, copies it into the receiver, and enters `p256ScalarMult`. The assembly-backed precomputation path then calls `p256PointAddAsm` with an infinity operand, violating that function’s documented precondition and producing undefined results.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- `ScalarMult` is called with `q` at infinity.
- The scalar is exactly 32 bytes.
- The asm P-256 implementation path is used.

## Proof

- Infinity is reachable from `NewP256Point` or `SetBytes({0})`.
- `ScalarMult` checks only scalar length, then executes `r.Set(q).p256ScalarMult(scalar)`.
- `p256ScalarMult` stores the input point in `precomp[0]`, doubles it, and then calls `p256PointAddAsm(&t0, &t0, p)`.
- With `p` still infinity, this violates the documented `p256PointAddAsm` contract: if either input is infinity, `res` and the return value are undefined.
- The legacy public `crypto/elliptic` wrapper maps affine `(0,0)` to infinity and calls `p.ScalarMult(p, scalar)`, making the invariant violation reachable through normal API inputs.

## Why This Is A Real Bug

The asm helper explicitly excludes infinity operands, but `ScalarMult` does not enforce that precondition before passing an infinity point into precomputation. The reachable path therefore depends on undefined internal behavior for a valid infinity representation. The reproduced impact is malformed or undefined P-256 results; no memory-safety impact is established.

## Fix Requirement

Reject an infinity input point before entering `p256ScalarMult`, or handle infinity as a special case before any precomputation that calls `p256PointAddAsm`.

## Patch Rationale

The patch adds an infinity check in the asm `ScalarMult` path before precomputation. This preserves the documented `p256PointAddAsm` invariant and prevents infinity operands from reaching assembly routines with undefined behavior.

## Residual Risk

None

## Patch

`035-scalarmult-violates-infinity-precondition.patch`