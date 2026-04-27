# Ord Inconsistent With Eq for NVariantOp

## Classification

Invariant violation, medium severity.

## Affected Locations

`library/stdarch/crates/stdarch-gen-arm/src/input.rs:66`

## Summary

`InputType` derives `Eq`, but its manual `Ord` implementation treated all `InputType::NVariantOp(Some(_))` values as equal. Different `WildString` operands therefore compared as `Ordering::Equal` while remaining unequal under `Eq`, violating Rust's required consistency between `Ord` and `Eq`.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

Two `InputType::NVariantOp(Some)` values contain different `WildString` operands.

## Proof

`InputType` derives `PartialEq` and `Eq`, so these values are unequal:

```rust
InputType::NVariantOp(Some("op2".parse().unwrap()))
InputType::NVariantOp(Some("op3".parse().unwrap()))
```

Before the patch, `Ord::cmp` handled all `NVariantOp` pairs with:

```rust
(InputType::NVariantOp(None), InputType::NVariantOp(Some(..))) => Less,
(InputType::NVariantOp(Some(..)), InputType::NVariantOp(None)) => Greater,
(InputType::NVariantOp(_), InputType::NVariantOp(_)) => Equal,
```

Thus `NVariantOp(Some("op2"))` and `NVariantOp(Some("op3"))` compared as `Equal`, despite `Eq` reporting them as different.

The operands are real inputs, not artificial values: `IntrinsicInput.n_variant_op` is stored as `InputType::NVariantOp(Some(...))`, and committed specs contain operands such as `op2` and `op3`.

## Why This Is A Real Bug

Rust ordered collections and ordering-based deduplication rely on the invariant that `a.cmp(&b) == Equal` if and only if `a == b`.

With the prior implementation, an ordered container such as `BTreeSet<InputType>` would treat:

```rust
InputType::NVariantOp(Some("op2".parse().unwrap()))
InputType::NVariantOp(Some("op3".parse().unwrap()))
```

as the same key, even though `Eq` says they are distinct. This can cause dropped entries, incorrect lookups, or unstable behavior in sorted/deduplicated data structures using `InputType` or derived `InputSet` ordering.

## Fix Requirement

Compare the contained `Option<WildString>` values for `InputType::NVariantOp` instead of collapsing all `Some(_)` operands to `Ordering::Equal`.

## Patch Rationale

The patch replaces the special-case `None`/`Some` ordering and unconditional equality fallback with:

```rust
(InputType::NVariantOp(op1), InputType::NVariantOp(op2)) => op1.cmp(op2),
```

This preserves the existing `None < Some(_)` ordering from `Option::cmp` while also comparing distinct `Some(WildString)` operands. As a result, `Ord` now distinguishes the same values that derived `Eq` distinguishes.

## Residual Risk

None

## Patch

```diff
diff --git a/library/stdarch/crates/stdarch-gen-arm/src/input.rs b/library/stdarch/crates/stdarch-gen-arm/src/input.rs
index adefbf3215b..034098e4c0f 100644
--- a/library/stdarch/crates/stdarch-gen-arm/src/input.rs
+++ b/library/stdarch/crates/stdarch-gen-arm/src/input.rs
@@ -70,9 +70,7 @@ fn cmp(&self, other: &Self) -> std::cmp::Ordering {
             (InputType::PredicateForm(pf1), InputType::PredicateForm(pf2)) => pf1.cmp(pf2),
             (InputType::Type(ty1), InputType::Type(ty2)) => ty1.cmp(ty2),
 
-            (InputType::NVariantOp(None), InputType::NVariantOp(Some(..))) => Less,
-            (InputType::NVariantOp(Some(..)), InputType::NVariantOp(None)) => Greater,
-            (InputType::NVariantOp(_), InputType::NVariantOp(_)) => Equal,
+            (InputType::NVariantOp(op1), InputType::NVariantOp(op2)) => op1.cmp(op2),
 
             (InputType::Type(..), InputType::PredicateForm(..)) => Less,
             (InputType::PredicateForm(..), InputType::Type(..)) => Greater,
```