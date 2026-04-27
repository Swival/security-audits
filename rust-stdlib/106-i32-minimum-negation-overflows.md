# i32 Minimum Negation Overflows

## Classification

Invariant violation, medium severity.

## Affected Locations

`library/std/src/sys/pal/hermit/mod.rs:102`

## Summary

Hermit syscall error conversion routes negative return values through `cvt<T>`, which calls `t.negate()` before constructing `io::Error::from_raw_os_error`.

For `i32`, `negate()` used direct arithmetic negation:

```rust
-(*self)
```

If the syscall wrapper returns `i32::MIN`, this expression attempts to compute `2147483648`, which is not representable as `i32`. With overflow checks enabled this panics; without overflow checks it wraps and preserves `i32::MIN`, producing an invalid raw OS error conversion result.

## Provenance

Verified from the supplied source, reproducer summary, and patch.

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Hermit syscall wrapper returns `i32::MIN` through `cvt`.
- The value reaches `IsNegative for i32::negate()`.

## Proof

Negative syscall results enter `cvt<T>`:

```rust
pub fn cvt<T: IsNegative>(t: T) -> io::Result<T> {
    if t.is_negative() { Err(io::Error::from_raw_os_error(t.negate())) } else { Ok(t) }
}
```

The affected `i32` implementation was:

```rust
impl IsNegative for i32 {
    fn is_negative(&self) -> bool {
        *self < 0
    }

    fn negate(&self) -> i32 {
        -(*self)
    }
}
```

For `i32::MIN`, direct negation overflows because the positive magnitude is unrepresentable in `i32`.

The reproducer confirmed:

- `cvt(i32::MIN)` panics with overflow checks enabled: `attempt to negate with overflow`.
- With overflow checks disabled, negation wraps and returns `Err(-2147483648)`.
- Hermit syscall results are passed into this helper from call sites including `library/std/src/sys/fs/hermit.rs:344`, `library/std/src/sys/net/connection/socket/hermit.rs:40`, and `library/std/src/sys/time/hermit.rs:10`.

## Why This Is A Real Bug

This is a real invariant violation because `cvt` is the generic Hermit syscall result converter and accepts `i32` values directly. Its negative branch assumes that negating a negative syscall result always yields a valid positive raw OS error code.

That assumption fails for exactly one `i32` value: `i32::MIN`.

Under the stated precondition, the implementation either:

- panics in checked-overflow builds, or
- wraps in unchecked-overflow builds and passes a negative raw OS error to `io::Error::from_raw_os_error`.

Hermit's normal errno constants are small positive values, so the practical trigger requires an anomalous or malformed syscall return of `i32::MIN`. The bug is still valid because the generic conversion helper does not enforce or defend the narrower errno domain before performing overflowing arithmetic.

## Fix Requirement

Avoid direct `i32` negation for `i32::MIN`.

The implementation must either:

- use checked negation and handle `i32::MIN` explicitly,
- widen before negating and validate the result, or
- use a non-panicking operation that preserves a valid `i32` result.

## Patch Rationale

The patch replaces direct negation with saturating negation:

```diff
-        -(*self)
+        (*self).saturating_neg()
```

`i32::saturating_neg()` returns `i32::MAX` for `i32::MIN`, avoiding overflow in both checked and unchecked builds.

For all other negative `i32` values, it behaves like normal negation and preserves existing syscall errno conversion behavior.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/pal/hermit/mod.rs b/library/std/src/sys/pal/hermit/mod.rs
index 53f6ddd7065..226464b99e8 100644
--- a/library/std/src/sys/pal/hermit/mod.rs
+++ b/library/std/src/sys/pal/hermit/mod.rs
@@ -99,7 +99,7 @@ fn is_negative(&self) -> bool {
     }
 
     fn negate(&self) -> i32 {
-        -(*self)
+        (*self).saturating_neg()
     }
 }
 impl_is_negative! { i8 i16 i64 isize }
```