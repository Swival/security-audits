# unchecked_div_exact rejects valid negative divisors

## Classification

Validation gap, medium severity, confidence certain.

## Affected Locations

`library/core/src/num/int_macros.rs:1197`

## Summary

`unchecked_div_exact` documents undefined behavior only for zero divisors, non-exact division, or the signed `MIN / -1` overflow case. Its unsafe precondition check was stricter than that contract because it required `rhs > 0`, causing valid exact divisions by negative divisors to fail UB-check/debug builds.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

A caller uses the unstable `exact_div` API and calls `unchecked_div_exact` with a valid negative exact divisor.

Example: `unsafe { 6i32.unchecked_div_exact(-2) }`.

## Proof

The documented safety contract states UB occurs when:

- `rhs == 0`
- `self % rhs != 0`
- `self == MIN && rhs == -1`

For `6i32.unchecked_div_exact(-2)`:

- `rhs` is not zero.
- `6 % -2 == 0`.
- `self` is not `i32::MIN`, so the `MIN / -1` overflow case does not apply.

The call reaches `assert_unsafe_precondition!` in `library/core/src/num/int_macros.rs`, but the checked predicate was:

```rust
rhs > 0 && lhs % rhs == 0 && (lhs != <$SelfT>::MIN || rhs != -1)
```

Because `-2 > 0` is false, the precondition rejects a call that satisfies the documented contract. The reproduced behavior confirms `6i32.unchecked_div_exact(-2)` aborts with:

```text
i32::unchecked_div_exact cannot overflow, divide by zero, or leave a remainder
```

## Why This Is A Real Bug

The implementation rejects valid inputs accepted by its own safety documentation and by `checked_div_exact`. This makes the unsafe precondition checker stricter than the actual API contract and causes false UB-check failures for every exact negative divisor, despite `intrinsics::exact_div` being called only after the caller satisfies the documented no-zero, no-remainder, no-overflow requirements.

## Fix Requirement

The unsafe precondition must reject zero divisors, not all non-positive divisors. The predicate must permit negative exact divisors while still preventing modulo by zero and the signed overflow case.

## Patch Rationale

Changing `rhs > 0` to `rhs != 0` aligns the precondition with the documented safety contract:

- Still rejects `rhs == 0`.
- Still verifies exact divisibility via `lhs % rhs == 0`.
- Still rejects `MIN / -1`.
- Allows valid exact negative divisors such as `6 / -2`.

## Residual Risk

None

## Patch

```diff
diff --git a/library/core/src/num/int_macros.rs b/library/core/src/num/int_macros.rs
index deda734263a..23049347b1f 100644
--- a/library/core/src/num/int_macros.rs
+++ b/library/core/src/num/int_macros.rs
@@ -1194,7 +1194,7 @@ pub const fn div_exact(self, rhs: Self) -> Option<Self> {
                 (
                     lhs: $SelfT = self,
                     rhs: $SelfT = rhs,
-                ) => rhs > 0 && lhs % rhs == 0 && (lhs != <$SelfT>::MIN || rhs != -1),
+                ) => rhs != 0 && lhs % rhs == 0 && (lhs != <$SelfT>::MIN || rhs != -1),
             );
             // SAFETY: Same precondition
             unsafe { intrinsics::exact_div(self, rhs) }
```