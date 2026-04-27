# Unguarded Immediate Maximum Increment

## Classification

Validation gap, medium severity. Confidence: certain.

## Affected Locations

`library/stdarch/crates/intrinsic-test/src/arm/json_parser.rs:138`

## Summary

`ArgPrep::Immediate` accepts JSON `minimum` and `maximum` values as `i64` without validating that `maximum` can be safely converted from an inclusive upper bound to an exclusive Rust range bound. When `minimum != maximum` and `maximum == i64::MAX`, `Constraint::Range(min..max + 1)` overflows during parsing.

## Provenance

Verified from the supplied source, reproducer, and patch. Report provenance includes Swival Security Scanner: https://swival.dev

## Preconditions

A Neon JSON intrinsic contains `Arguments_Preparation` metadata for an argument with:

- `minimum != maximum`
- `maximum = 9223372036854775807`

## Proof

JSON input is deserialized into:

```rust
ArgPrep::Immediate { min, max }
```

`get_neon_intrinsics` filters entries where `SIMD_ISA == "Neon"`, calls `json_to_intrinsic`, and converts argument preparation metadata through:

```rust
let constraint: Option<Constraint> = arg_prep.and_then(|a| a.try_into().ok());
```

The failing conversion is:

```rust
Ok(Constraint::Range(min..max + 1))
```

At `library/stdarch/crates/intrinsic-test/src/arm/json_parser.rs:138`, `max + 1` overflows when `max == i64::MAX`.

The reproduced trigger was a minimal Neon JSON file with:

```json
"minimum": 0,
"maximum": 9223372036854775807
```

Running `intrinsic-test --generate-only` reached this path and panicked at `json_parser.rs:138:43` with:

```text
attempt to add with overflow
```

## Why This Is A Real Bug

The code treats JSON immediate bounds as trusted and converts an inclusive `maximum` into an exclusive range bound by incrementing it. `i64::MAX` is accepted by deserialization but cannot be incremented. In debug/dev builds this causes a panic during parsing before generation/building completes. In optimized builds, unchecked overflow can wrap to `i64::MIN`, producing an invalid or empty exclusive range rather than the intended inclusive maximum.

## Fix Requirement

The conversion must reject or otherwise safely handle non-equal immediate ranges whose inclusive maximum is `i64::MAX`. A valid fix is to validate `max < i64::MAX` before computing `max + 1`, or to represent the constraint with an inclusive range that does not require incrementing the upper bound.

## Patch Rationale

The patch preserves existing behavior for valid inputs:

```rust
if min == max {
    Ok(Constraint::Equal(min))
} else if max < i64::MAX {
    Ok(Constraint::Range(min..max + 1))
} else {
    Err(())
}
```

This prevents the overflow by only evaluating `max + 1` when the increment is representable. Inputs with `min == max == i64::MAX` remain valid as `Constraint::Equal(i64::MAX)`. Inputs requiring a non-singleton inclusive range ending at `i64::MAX` are rejected instead of panicking or wrapping.

## Residual Risk

None

## Patch

```diff
diff --git a/library/stdarch/crates/intrinsic-test/src/arm/json_parser.rs b/library/stdarch/crates/intrinsic-test/src/arm/json_parser.rs
index c1563a7364c..a6a157f7c20 100644
--- a/library/stdarch/crates/intrinsic-test/src/arm/json_parser.rs
+++ b/library/stdarch/crates/intrinsic-test/src/arm/json_parser.rs
@@ -134,8 +134,10 @@ fn try_from(prep: ArgPrep) -> Result<Self, Self::Error> {
         if let Ok((min, max)) = parsed_ints {
             if min == max {
                 Ok(Constraint::Equal(min))
-            } else {
+            } else if max < i64::MAX {
                 Ok(Constraint::Range(min..max + 1))
+            } else {
+                Err(())
             }
         } else {
             Err(())
```