# Zero Denominator In Duration Ceil Division

## Classification

- Type: validation gap
- Severity: medium
- Confidence: certain
- Impact: panic or abort on reachable public API input, causing denial of service where the denominator is attacker-controlled
- Memory safety impact: none indicated

## Affected Locations

- `library/core/src/time.rs:1243`
- `library/core/src/time.rs:1245`

## Summary

`Duration::div_duration_ceil` accepts a public `Duration` denominator but did not explicitly reject `Duration::ZERO`. The method converted `rhs` with `rhs.as_nanos()`, producing `0`, then passed that value directly to `u128::div_ceil`. Integer division by zero panics, so callers supplying a zero duration could trigger an unintended panic through this unstable public API.

## Provenance

- Source: Swival Security Scanner
- Scanner URL: https://swival.dev
- Finding: zero denominator in duration ceil division
- Reproduction status: reproduced

## Preconditions

- The caller enables the unstable `duration_integer_division` feature.
- The caller invokes `Duration::div_duration_ceil`.
- The `rhs` argument is `Duration::ZERO`.

## Proof

The vulnerable implementation was:

```rust
pub const fn div_duration_ceil(self, rhs: Duration) -> u128 {
    self.as_nanos().div_ceil(rhs.as_nanos())
}
```

For `rhs == Duration::ZERO`:

```rust
Duration::ZERO.as_nanos() == 0
```

That zero denominator reaches `u128::div_ceil`. The reproduced execution path confirms that `u128::div_ceil` performs integer division internally, and `rhs == 0` causes a runtime panic with:

```text
attempt to divide by zero
```

A reproducer calling:

```rust
Duration::from_secs(1).div_duration_ceil(Duration::ZERO)
```

panicked as expected.

## Why This Is A Real Bug

The panic is reachable through a public `Duration` method gated only by the unstable `duration_integer_division` feature. The denominator comes directly from the caller, and the method had no explicit zero-duration validation before invoking integer ceil division. In applications that pass untrusted or externally-derived duration values into this API, a zero denominator can reliably terminate the operation or abort the process depending on the panic strategy.

The neighboring scalar division API already documents and handles zero division deliberately, so the absence of an explicit guard here is a validation gap rather than an unavoidable implementation detail.

## Fix Requirement

`Duration::div_duration_ceil` must check `rhs.is_zero()` before calling `div_ceil` and define intentional behavior for zero-duration division.

The selected behavior is to panic explicitly with a duration-specific divide-by-zero message, matching Rust's existing division semantics while avoiding an implicit lower-level integer division panic.

## Patch Rationale

The patch adds a direct zero-duration guard:

```rust
if rhs.is_zero() {
    panic!("divide by zero error when dividing durations");
}
```

This preserves the existing return type and public API shape, keeps the function usable in const contexts, and makes the failure mode explicit before converting the denominator to nanoseconds. Non-zero inputs continue to use the existing `self.as_nanos().div_ceil(rhs.as_nanos())` implementation unchanged.

## Residual Risk

None

## Patch

```diff
diff --git a/library/core/src/time.rs b/library/core/src/time.rs
index 9073131b35b..f5f9df0439a 100644
--- a/library/core/src/time.rs
+++ b/library/core/src/time.rs
@@ -1243,6 +1243,9 @@ pub const fn div_duration_floor(self, rhs: Duration) -> u128 {
                   without modifying the original"]
     #[inline]
     pub const fn div_duration_ceil(self, rhs: Duration) -> u128 {
+        if rhs.is_zero() {
+            panic!("divide by zero error when dividing durations");
+        }
         self.as_nanos().div_ceil(rhs.as_nanos())
     }
 }
```