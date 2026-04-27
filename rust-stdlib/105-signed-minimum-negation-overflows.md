# Signed Minimum Negation Overflows

## Classification

Invariant violation, medium severity.

## Affected Locations

`library/std/src/sys/pal/hermit/mod.rs:91`

## Summary

Hermit syscall error conversion negated signed negative return values directly. If a syscall wrapper returned a signed minimum value, such as `i32::MIN` or `isize::MIN`, the negation overflowed before conversion to an `io::Error`.

The patch replaces direct negation with checked negation and maps unrepresentable signed-minimum cases to `i32::MAX`, avoiding overflow and preserving error-path behavior.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The Hermit syscall wrapper returns a signed minimum negative value.
- The result is passed through `cvt` or `cvt_r`.
- The value implements `IsNegative`.

## Proof

`cvt` checks whether the syscall return value is negative and then calls `t.negate()` to construct an OS error:

```rust
pub fn cvt<T: IsNegative>(t: T) -> io::Result<T> {
    if t.is_negative() { Err(io::Error::from_raw_os_error(t.negate())) } else { Ok(t) }
}
```

Before the patch, macro-generated implementations used:

```rust
i32::try_from(-(*self)).unwrap()
```

and the `i32` implementation used:

```rust
-(*self)
```

For signed minimum values, negation is not representable:

- `i32::MIN` overflows in the dedicated `i32` implementation.
- `i8::MIN`, `i16::MIN`, `i64::MIN`, and `isize::MIN` overflow in the macro implementation before `i32::try_from`.
- `cvt_r` repeatedly invokes syscall closures and forwards each result to `cvt`, so the same overflow is reachable through retrying syscall wrappers.

The reproduction confirmed that `cvt_r(|| i32::MIN)` panics with `attempt to negate with overflow` when overflow checks are enabled. It also confirmed that unchecked overflow can produce invalid negative errno behavior for `i32::MIN`.

Concrete reachable paths include:

- `library/std/src/sys/fd/hermit.rs:21`
- `library/std/src/sys/fd/hermit.rs:63`
- `library/std/src/sys/net/connection/socket/hermit.rs:50`

## Why This Is A Real Bug

The conversion routine is intended to turn negative syscall return values into `io::Error`. Instead, a valid machine-level signed integer value can cause panic/abort behavior or invalid errno propagation.

This violates the error-conversion invariant for Hermit platform syscall wrappers: negative syscall results should be represented as errors, not trigger arithmetic overflow during conversion.

## Fix Requirement

Avoid direct signed negation on potentially minimum signed values.

A correct fix must:

- Use checked negation or explicitly handle signed minimum values.
- Avoid panicking before constructing an `io::Error`.
- Avoid producing negative raw OS error codes from overflowed negation.
- Preserve normal conversion for representable negative errno values.

## Patch Rationale

The patch changes macro-generated `IsNegative::negate` implementations from unchecked negation to:

```rust
self.checked_neg().and_then(|n| i32::try_from(n).ok()).unwrap_or(i32::MAX)
```

This prevents overflow for signed minimum values and avoids panics when the negated value cannot fit in `i32`.

The dedicated `i32` implementation changes from unchecked negation to:

```rust
self.checked_neg().unwrap_or(i32::MAX)
```

This handles `i32::MIN` without overflow while preserving exact behavior for all representable errno values.

Mapping the impossible signed-minimum negation case to `i32::MAX` keeps execution on the error path and supplies a positive raw OS error code rather than panicking or propagating an overflowed negative value.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/pal/hermit/mod.rs b/library/std/src/sys/pal/hermit/mod.rs
index 53f6ddd7065..51ecd06ffaa 100644
--- a/library/std/src/sys/pal/hermit/mod.rs
+++ b/library/std/src/sys/pal/hermit/mod.rs
@@ -88,7 +88,7 @@ fn is_negative(&self) -> bool {
         }
 
         fn negate(&self) -> i32 {
-            i32::try_from(-(*self)).unwrap()
+            self.checked_neg().and_then(|n| i32::try_from(n).ok()).unwrap_or(i32::MAX)
         }
     })*)
 }
@@ -99,7 +99,7 @@ fn is_negative(&self) -> bool {
     }
 
     fn negate(&self) -> i32 {
-        -(*self)
+        self.checked_neg().unwrap_or(i32::MAX)
     }
 }
 impl_is_negative! { i8 i16 i64 isize }
```