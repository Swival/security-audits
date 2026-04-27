# Unchecked Cached Power Index

## Classification

Validation gap, low severity. Confidence: certain.

## Affected Locations

`library/core/src/num/imp/flt2dec/strategy/grisu.rs:128`

## Summary

`cached_power` computed a cached-power table index from caller-controlled `gamma` and indexed `CACHED_POW10` without validating that the computed index was within the table bounds. Out-of-range `gamma` values could produce a negative index later cast to `usize`, or an index greater than the final table entry, causing a bounds-check panic.

## Provenance

Reported and reproduced from Swival Security Scanner results: https://swival.dev

## Preconditions

A caller invokes `cached_power` with `gamma` outside the cached exponent range.

## Proof

`cached_power` computes:

```rust
let idx = ((gamma as i32) - offset) * range / domain;
let (f, e, k) = CACHED_POW10[idx as usize];
```

`CACHED_POW10` has length 81, so valid indices are `0..=80`.

If `gamma` is below `CACHED_POW10_FIRST_E`, `idx` can be negative and then cast to a very large `usize`. If `gamma` is above the supported range, `idx` can exceed 80. In both cases the subsequent table access panics.

The function is directly reachable because `cached_power` is `pub` and doc-hidden within the crate. It is also indirectly reachable through formatting helpers such as `format_exact_opt`, which accepts a `Decoded`, normalizes it, and calls `cached_power`.

A reproduced indirect case uses `Decoded { mant: 1, exp: 1081, ... }` with a non-empty buffer. This passes `format_exact_opt` assertions, normalizes to `v.e = 1018`, computes `gamma = -1114`, and panics at the cached-power table index.

## Why This Is A Real Bug

The table access is performed before any runtime validation of `idx`. Rust slice indexing is bounds-checked, so the impact is a panic rather than memory corruption. For callers of these internal unstable APIs, crafted inputs can therefore cause an abortable denial of service.

## Fix Requirement

Validate that the computed index is within the legal `CACHED_POW10` index range before indexing the table.

## Patch Rationale

The patch adds an assertion immediately after computing `idx`:

```rust
assert!((0..=range).contains(&idx));
```

This converts the implicit bounds-check panic from the table access into an explicit contract check at the point where the invalid value is created. It prevents negative `idx` values from being cast to `usize` and documents the required invariant before indexing.

## Residual Risk

None

## Patch

```diff
diff --git a/library/core/src/num/imp/flt2dec/strategy/grisu.rs b/library/core/src/num/imp/flt2dec/strategy/grisu.rs
index f7ee4658293..d433fc54a2d 100644
--- a/library/core/src/num/imp/flt2dec/strategy/grisu.rs
+++ b/library/core/src/num/imp/flt2dec/strategy/grisu.rs
@@ -124,6 +124,7 @@ pub fn cached_power(alpha: i16, gamma: i16) -> (i16, Fp) {
     let range = (CACHED_POW10.len() as i32) - 1;
     let domain = (CACHED_POW10_LAST_E - CACHED_POW10_FIRST_E) as i32;
     let idx = ((gamma as i32) - offset) * range / domain;
+    assert!((0..=range).contains(&idx));
     let (f, e, k) = CACHED_POW10[idx as usize];
     debug_assert!(alpha <= e && e <= gamma);
     (k, Fp { f, e })
```