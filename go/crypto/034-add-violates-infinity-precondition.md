# Add Violates Infinity Precondition

## Classification

Invariant violation. Severity: medium. Confidence: certain.

## Affected Locations

`src/crypto/internal/fips140/nistec/p256_asm.go:398`

## Summary

`P256Point.Add` accepted infinity operands but called `p256PointAddAsm` before handling them. The assembly helper explicitly requires both inputs to be non-infinity; when either operand has `z == 0`, its result and equality return are undefined. `Add` then consumed the undefined return in `p256MovCond` before later conditional moves selected the intended infinity/other operand result.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

## Preconditions

Either `Add` operand is the point at infinity, i.e. has `z == 0`.

Reachable sources include:

- `NewP256Point` returning infinity.
- `SetBytes([]byte{0})` accepting infinity.
- `crypto/elliptic` mapping `(0, 0)` to infinity before forwarding through `Curve.Add`.

## Proof

The reachable path is:

- `NewP256Point` returns infinity at `src/crypto/internal/fips140/nistec/p256_asm.go:47`.
- `SetBytes([]byte{0})` accepts infinity at `src/crypto/internal/fips140/nistec/p256_asm.go:86`.
- `crypto/elliptic` maps `(0, 0)` to infinity at `src/crypto/elliptic/nistec.go:135`.
- `Curve.Add` forwards to `p1.Add(p1, p2)` at `src/crypto/elliptic/nistec.go:170`.
- `P256Point.Add` records `r1IsInfinity` and `r2IsInfinity`, but still calls `p256PointAddAsm(&sum, r1, r2)` at `src/crypto/internal/fips140/nistec/p256_asm.go:398`.
- `p256PointAddAsm` has an assembly contract that leaves both `res` and return value undefined if either input is infinity.
- The undefined return value is consumed immediately by `p256MovCond` at `src/crypto/internal/fips140/nistec/p256_asm.go:402`.
- Only afterward do `src/crypto/internal/fips140/nistec/p256_asm.go:403` and `src/crypto/internal/fips140/nistec/p256_asm.go:404` select the infinity operand or other operand.

The final point may be overwritten correctly by later conditional moves in current assembly behavior, but the invalid call and use of an undefined return are real and reachable.

## Why This Is A Real Bug

The code violates the documented precondition of `p256PointAddAsm`. Undefined outputs from an assembly primitive are not valid intermediate values, especially when the undefined return is immediately used to select between computed results. Even if current behavior often produces the intended final point, correctness depends on behavior the contract explicitly does not guarantee.

## Fix Requirement

Handle infinity operands before calling `p256PointAddAsm`, so the assembly helper is invoked only when both inputs are non-infinity.

## Patch Rationale

`034-add-violates-infinity-precondition.patch` moves the infinity handling ahead of the assembly call. This preserves the existing mathematical behavior for infinity cases while ensuring `p256PointAddAsm` only receives valid non-infinity operands. Non-infinity additions continue to use the existing assembly path.

## Residual Risk

None

## Patch

`034-add-violates-infinity-precondition.patch`