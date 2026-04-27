# char minimum underflows before validation

## Classification

Invariant violation, medium severity.

## Affected Locations

`library/core/src/pat.rs:72`

## Summary

`RangePattern::sub_one` for `char` subtracts one from `self as u32` before checking whether the input is `char::MIN`. For `char::MIN`, this performs `0u32 - 1` before `char::from_u32` can reject the value, bypassing the intended minimum-value panic path.

A reproduced adjacent failure confirms the same implementation also mishandles exclusive ranges ending at the first valid scalar after the surrogate gap: `'\0'..'\u{E000}'` should lower to an inclusive end of `'\u{D7FF}'`, but the current subtraction produces surrogate `0xDFFF`, causing a panic.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

`RangePattern::sub_one` is called on `char::MIN`.

Reachability is through exclusive range lowering, which calls the `RangeSub` lang item and resolves to `RangePattern::sub_one` for `char`.

## Proof

The affected implementation is:

```rust
fn sub_one(self) -> Self {
    match char::from_u32(self as u32 - 1) {
        None => panic!("exclusive range to start of valid chars"),
        Some(val) => val,
    }
}
```

For `self == char::MIN`, `self as u32` is `0`, so the expression `self as u32 - 1` underflows before `char::from_u32` executes.

The reproduced narrower failure uses:

```rust
pattern_type!(char is '\0'..'\u{E000}')
```

Exclusive range lowering calls `RangeSub`, which reaches `RangePattern::sub_one`. The implementation computes:

```text
0xE000 - 1 == 0xDFFF
```

`0xDFFF` is a surrogate and not a valid `char`, so `char::from_u32` returns `None` and the compiler reports:

```text
evaluation panicked: exclusive range to start of valid chars
```

This rejects a valid exclusive range whose inclusive end should be `'\u{D7FF}'`.

## Why This Is A Real Bug

The implementation assumes that subtracting one from a Unicode scalar value yields the previous valid Unicode scalar value. That assumption is false at two boundaries:

- At `char::MIN`, subtraction underflows before validation.
- At `'\u{E000}'`, subtraction lands inside the surrogate range instead of skipping to `'\u{D7FF}'`.

The verified finding concerns the first case: the minimum-value guard is missing before arithmetic, so the intended invariant-preserving panic is not reliably reached.

## Fix Requirement

Check `self == char::MIN` before subtracting, then panic explicitly with the existing error message.

## Patch Rationale

The patch moves minimum-value validation ahead of arithmetic:

```rust
if self == char::MIN {
    panic!("exclusive range to start of valid chars");
}
```

This prevents `0u32 - 1` from executing for `char::MIN` and preserves the existing panic behavior for invalid exclusive range starts.

## Residual Risk

None

## Patch

```diff
diff --git a/library/core/src/pat.rs b/library/core/src/pat.rs
index 2670c261419..be3bd1f0eb1 100644
--- a/library/core/src/pat.rs
+++ b/library/core/src/pat.rs
@@ -70,6 +70,9 @@ impl const RangePattern for char {
     const MAX: Self = char::MAX;
 
     fn sub_one(self) -> Self {
+        if self == char::MIN {
+            panic!("exclusive range to start of valid chars");
+        }
         match char::from_u32(self as u32 - 1) {
             None => panic!("exclusive range to start of valid chars"),
             Some(val) => val,
```