# divMod omits BigInt zero-divisor check

## Classification
- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations
- `std/bigint.d:1701`

## Summary
`divMod` accepted a zero-valued `BigInt` divisor without performing the same entrypoint validation used by `/=` and `%=`. It forwarded `divisor.data` directly into `BigUint.divMod`, allowing division by zero to reach the arithmetic core.

## Provenance
- Verified from the supplied reproducer and patch context
- Scanner source: https://swival.dev

## Preconditions
- Caller passes zero `BigInt` divisor to `divMod`

## Proof
- `divMod` in `std/bigint.d:1701` accepted arbitrary `BigInt divisor` and immediately called `BigUint.divMod(dividend.data, divisor.data, q, r)` without `checkDivByZero()`.
- Debug builds failed only in a lower-level assertion at `std/internal/math/biguintcore.d:894` (`assert(y != 0, "BigUint division by zero")`), proving the invariant was not enforced at the `BigInt` API boundary.
- Release builds compiled that assertion out.
- With `y == 0`, `divInt!uint` entered `for (; y != 1; y >>= 1)` at `std/internal/math/biguintcore.d:897`; shifting zero right leaves zero, so the loop never terminates.
- Reachable call path from the reproducer: `std/bigint.d:2297` -> `std/internal/math/biguintcore.d:979` -> `std/internal/math/biguintcore.d:990` -> `std/internal/math/biguintcore.d:885`.

## Why This Is A Real Bug
The public `BigInt` division API is expected to reject zero divisors before entering low-level arithmetic. This entrypoint violated that contract. In debug builds it surfaced as an unintended internal assertion; in release builds it could hang indefinitely. That is a real, reachable denial-of-service condition from a direct `divMod` call.

## Fix Requirement
Add `divisor.checkDivByZero();` at `divMod` entry before invoking `BigUint.divMod`.

## Patch Rationale
The patch restores consistent zero-divisor validation at the `BigInt` boundary, matching existing `/=` and `%=` behavior and preventing unchecked zero from reaching `BigUint` internals.

## Residual Risk
None

## Patch
- Patch file: `048-divmod-omits-bigint-zero-divisor-check.patch`
- Change: insert `divisor.checkDivByZero();` at `divMod` entry in `std/bigint.d` before the call into `BigUint.divMod`