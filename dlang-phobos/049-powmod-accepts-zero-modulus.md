# powmod accepts zero modulus

## Classification
Validation gap; medium severity; confidence: certain.

## Affected Locations
- `std/bigint.d:2389` (BigInt overload)
- `std/bigint.d:2400`
- `std/bigint.d:492`
- `std/bigint.d:1525`
- `std/math/exponential.d:730` (unsigned integer overload)

## Summary
Both `powmod` overloads accept `modulus == 0` and use that value as the divisor in modular arithmetic. In the `BigInt` overload, zero modulus reaches `checkDivByZero()`, which fires an assertion and aborts in debug builds. In the unsigned integer overload (`std/math/exponential.d`), zero modulus reaches `mulmod(..., 0)`, producing target-dependent nonsense values instead of rejecting undefined input.

## Provenance
Verified from reproducers against both overloads in the committed tree. Scanner reference: https://swival.dev

## Preconditions
Caller passes zero modulus to either `powmod` overload.

## Proof

### BigInt overload (`std/bigint.d`)
```d
powmod(BigInt(2), BigInt(1), BigInt(0));
```
- `powmod` enters the loop with `exponent == 1`
- `auto tmp = base % modulus` executes at `std/bigint.d:2400`
- `BigInt % BigInt` checks the divisor via `y.checkDivByZero()` at `std/bigint.d:492`
- `checkDivByZero()` asserts `!isZero()` at `std/bigint.d:1525`
- Zero modulus triggers assertion failure and abort

### Unsigned integer overload (`std/math/exponential.d`)
```d
powmod(2u, 1u, 0u);   // returns 2
powmod(2u, 2u, 0u);   // returns 4
```
- `powmod` copies `m` into `modulus` without validation
- The square-and-multiply loop invokes `mulmod(result, base, modulus)` with `modulus == 0`
- Some `% 0` cases evaluate to bogus values rather than trapping, yielding incorrect results

## Why This Is A Real Bug
Modular exponentiation is undefined for modulus zero. Both overloads allow execution to continue with arithmetic that has no valid mathematical result. The BigInt path produces denial of service via assertion abort; the unsigned path yields compiler- and target-dependent nonsense. Both are observable incorrect behavior from public API calls requiring no corrupted state.

## Fix Requirement
Reject `modulus == 0` at `powmod` entry in both overloads before any modular operation.

## Patch Rationale
The patches add early zero-modulus checks in both overloads, making the invalid precondition explicit at the API boundary and preventing all downstream `% 0` operations. This preserves existing behavior for valid moduli and fails fast on the only invalid input.

## Residual Risk
None

## Patches
- `049-powmod-accepts-zero-modulus-and-hits-assertion-path.patch` -- validates modulus in `std/bigint.d`
- `071-powmod-divides-by-zero-when-modulus-is-zero.patch` -- validates modulus in `std/math/exponential.d`
