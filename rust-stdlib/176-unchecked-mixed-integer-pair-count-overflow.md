# unchecked mixed integer pair count overflow

## Classification

Data integrity bug, medium severity.

## Affected Locations

`library/compiler-builtins/libm-test/src/generate/random.rs:164`

## Summary

Integer-pair random test case generation returned `count0 * count1` without checked overflow handling. When both per-argument iteration counts multiply above `u64::MAX`, release builds silently wrap the reported case count before `get_test_cases` wraps the iterator in `KnownSize`. This corrupts the advertised iterator size and can make downstream consumers trust an impossible `ExactSizeIterator` contract.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- A random integer-pair input implementation is selected.
- The configured iteration count causes `iteration_count(ctx, 0) * iteration_count(ctx, 1)` to exceed `u64::MAX`.
- Release-mode arithmetic is used, allowing unchecked `u64` multiplication to wrap.

## Proof

`ride_iterations` is public at `library/compiler-builtins/libm-test/src/run_cfg.rs:116`.

With a two-argument random integer operation and `override_iterations(u64::MAX)`, `iteration_count` computes `ceil(sqrt(u64::MAX as f64)) == 4294967296` at `library/compiler-builtins/libm-test/src/run_cfg.rs:318`.

That gives:

```text
count0 = 2^32
count1 = 2^32
count0 * count1 = 2^64
```

The affected integer-pair implementation returned the expected count as:

```rust
(iter, count0 * count1)
```

In release mode this wraps to `0`, even though the product iterator still has cases to yield.

An equivalent release-mode runtime demo confirmed:

```text
count0 = count1 = 1 << 32
reported = 0
```

The iterator still yielded cases, and `KnownSize::size_hint()` changed from `(0, Some(0))` before iteration to `(18446744073709551615, Some(...))` after one item, demonstrating a false size contract.

## Why This Is A Real Bug

Nearby random input implementations already use `strict_mul` for equivalent pair and triple product counts, including float pairs and mixed float/integer pairs. The affected integer-pair path was inconsistent and allowed silent count corruption.

`KnownSize` validates the iterator against the already-wrapped count, not the mathematical product. Therefore the wrapper can advertise and enforce the wrong size instead of detecting overflow. Consumers may skip progress or work based on a reported count of `0`, preallocate incorrectly, or rely on invalid `size_hint` / `ExactSizeIterator` behavior.

## Fix Requirement

Replace the unchecked multiplication with checked strict multiplication:

```rust
count0.strict_mul(count1)
```

The operation must fail instead of silently wrapping when the expected random test case count does not fit in `u64`.

## Patch Rationale

The patch changes the affected integer-pair count calculation to match the existing strict arithmetic pattern used by nearby product-count implementations.

Before:

```rust
(iter, count0 * count1)
```

After:

```rust
(iter, count0.strict_mul(count1))
```

This preserves behavior for valid products and prevents release-mode silent overflow for invalid products.

## Residual Risk

None

## Patch

```diff
diff --git a/library/compiler-builtins/libm-test/src/generate/random.rs b/library/compiler-builtins/libm-test/src/generate/random.rs
index 32bd2f24ee0..cfeb53bbea8 100644
--- a/library/compiler-builtins/libm-test/src/generate/random.rs
+++ b/library/compiler-builtins/libm-test/src/generate/random.rs
@@ -160,7 +160,7 @@ fn get_cases(ctx: &CheckCtx) -> (impl Iterator<Item = Self>, u64) {
                 let iter0 = random_ints(count0, range0);
                 let iter1 = random_ints(count1, range1.clone());
                 let iter = product2(iter0, iter1);
-                (iter, count0 * count1)
+                (iter, count0.strict_mul(count1))
             }
         }
     };
```