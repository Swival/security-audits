# Zero Denominator in Duration Floor Division

## Classification

Validation gap; reachable division-by-zero panic in a public duration division API.

Severity: medium.

Confidence: certain.

## Affected Locations

`library/core/src/time.rs:1133`

`library/core/src/time.rs:1225`

## Summary

`Duration::div_duration_floor` accepted a `Duration` divisor without checking whether it was zero. When `rhs == Duration::ZERO`, `rhs.as_nanos()` returns `0`, and that value was passed directly into `u128::div_floor`, which performs integer division and panics on a zero denominator.

This allows any caller that forwards an unchecked or untrusted divisor duration into `div_duration_floor` to trigger a panic or abort path.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced from source inspection and patched in `047-zero-denominator-in-duration-floor-division.patch`.

## Preconditions

A caller invokes:

```rust
Duration::div_duration_floor(Duration::ZERO)
```

The API is `pub const fn` and gated only by the unstable `duration_integer_division` feature, so nightly callers using that feature can reach it directly.

## Proof

The vulnerable implementation was:

```rust
pub const fn div_duration_floor(self, rhs: Duration) -> u128 {
    self.as_nanos().div_floor(rhs.as_nanos())
}
```

For `rhs == Duration::ZERO`:

```rust
pub const ZERO: Duration = Duration::from_nanos(0);
```

`Duration::as_nanos()` computes:

```rust
self.secs as u128 * NANOS_PER_SEC as u128 + self.nanos.as_inner() as u128
```

For zero duration, that returns `0`.

Therefore the call becomes:

```rust
self.as_nanos().div_floor(0)
```

For unsigned integers, `div_floor` is implemented as division by `rhs` and documents a panic when `rhs` is zero. The zero denominator is reachable with no prior validation.

## Why This Is A Real Bug

The panic is reachable through a public API with a valid `Duration` value. `Duration::ZERO` is a stable, normal value, not an invalid internal state.

The issue is not memory unsafe, but it is a real denial-of-service style failure for callers that accept a divisor duration from user input, configuration, network data, or another unchecked source.

The neighboring scalar division API already defines explicit divide-by-zero behavior through `checked_div` and `Div<u32>`, so allowing the panic to occur implicitly inside `div_floor` is an API validation gap.

## Fix Requirement

`div_duration_floor` must explicitly check for a zero divisor before performing integer division and must define the panic behavior at the API boundary.

## Patch Rationale

The patch adds an explicit zero-duration guard:

```rust
if rhs.is_zero() {
    panic!("divide by zero error when dividing durations");
}
```

This prevents the denominator from silently propagating into `div_floor(0)` and makes the failure mode intentional, local, and consistent with existing duration division panic wording.

The check uses `Duration::is_zero()`, which directly tests the internal seconds and nanoseconds fields and is already available as a const-stable method.

## Residual Risk

None

## Patch

```diff
diff --git a/library/core/src/time.rs b/library/core/src/time.rs
index 9073131b35b..02cdd49ea81 100644
--- a/library/core/src/time.rs
+++ b/library/core/src/time.rs
@@ -1223,6 +1223,9 @@ pub const fn div_duration_f32(self, rhs: Duration) -> f32 {
                   without modifying the original"]
     #[inline]
     pub const fn div_duration_floor(self, rhs: Duration) -> u128 {
+        if rhs.is_zero() {
+            panic!("divide by zero error when dividing durations");
+        }
         self.as_nanos().div_floor(rhs.as_nanos())
     }
```