# clamp reduction unwraps removed maximum

## Classification

Denial of service, medium severity.

## Affected Locations

`src/css/values/calc.rs:412`

## Summary

`clamp()` reduction can remove the maximum argument, then later unwrap it as if it still exists. A comparable `center` value greater than `max` deterministically panics during CSS parsing, aborting bundling when panic mode is `abort`.

## Provenance

Verified by Swival.dev Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The bundler parses attacker-controlled CSS math functions.
- The attacker supplies a `clamp()` expression whose comparable center value exceeds the maximum value.
- The affected parser path handles the value through `Calc::parse_with`.

## Proof

A triggering CSS value follows the `LengthPercentage` parsing path, enters `Calc::<Self>::parse`, and reaches the `CalcUnit::Clamp` arm in `src/css/values/calc.rs`.

The clamp arguments parse as:

```rust
(Some(min), center, Some(max))
```

When `center` and `max` are both `Calc::Value` and are comparable, `DimensionPercentage::partial_cmp` can return `Ordering::Greater` for a value such as `clamp(0px, 20px, 10px)`.

The vulnerable branch executes:

```rust
let val = max.take().unwrap();
center = val;
```

This removes the `max` value and assigns it to `center`, leaving `max == None`.

The next selector was computed incorrectly:

```rust
let switch_val: u8 = ((min.is_some() as u8) << 1) | (min.is_some() as u8);
```

Because both bits use `min.is_some()`, a remaining `min` selects the `0b11` clamp case even though `max` is now `None`. That case calls:

```rust
max.unwrap()
```

This deterministically panics.

The workspace sets `panic = "abort"` in release-related profiles, so the panic can abort the bundling process.

## Why This Is A Real Bug

The panic is not dependent on race timing or environmental state. It follows directly from valid parser state mutation:

- `max.take()` sets `max` to `None`.
- `min` remains `Some`.
- The bit selector ignores `max.is_some()`.
- The selected branch unconditionally unwraps `max`.

Thus attacker-controlled CSS can turn normal parsing into a process-aborting panic.

## Fix Requirement

- Compute the final reduction case from both `min` and `max`.
- Do not call `unwrap()` on an `Option` whose state may have changed during reduction.
- Preserve the intended reductions:
  - no bounds: return `center`
  - only min: emit `max(min, center)`
  - only max: emit `min(max, center)`
  - both bounds: emit `clamp(min, center, max)`

## Patch Rationale

The patch replaces the synthetic bit selector and unsafe unwraps with exhaustive pattern matching over `(min, max)`.

This makes the option state explicit, consumes each present value exactly once, and prevents selecting a branch that requires a missing value.

## Residual Risk

None

## Patch

```diff
diff --git a/src/css/values/calc.rs b/src/css/values/calc.rs
index 1c5047dcb9..733f1650bf 100644
--- a/src/css/values/calc.rs
+++ b/src/css/values/calc.rs
@@ -431,19 +431,15 @@ impl<V: CalcValue> Calc<V> {
                     }
                 }
 
-                let switch_val: u8 = ((min.is_some() as u8) << 1) | (min.is_some() as u8);
-                // TODO(port): Zig original has a likely bug — both bits derive from `min != null`.
-                // Ported faithfully; Phase B should verify intended `(min, max)` packing.
-                Ok(match switch_val {
-                    0b00 => center,
-                    0b10 => Calc::Function(Box::new(MathFunction::Max(arr2(min.unwrap(), center)))),
-                    0b01 => Calc::Function(Box::new(MathFunction::Min(arr2(max.unwrap(), center)))),
-                    0b11 => Calc::Function(Box::new(MathFunction::Clamp {
-                        min: min.unwrap(),
+                Ok(match (min, max) {
+                    (None, None) => center,
+                    (Some(min), None) => Calc::Function(Box::new(MathFunction::Max(arr2(min, center)))),
+                    (None, Some(max)) => Calc::Function(Box::new(MathFunction::Min(arr2(max, center)))),
+                    (Some(min), Some(max)) => Calc::Function(Box::new(MathFunction::Clamp {
+                        min,
                         center,
-                        max: max.unwrap(),
+                        max,
                     })),
-                    _ => unreachable!(),
                 })
             }
             CalcUnit::Round => input.parse_nested_block(|i| {
```