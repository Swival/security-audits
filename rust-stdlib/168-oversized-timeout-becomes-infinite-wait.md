# Oversized Timeout Becomes Infinite Wait

## Classification

Logic error, medium severity. Confidence: certain.

## Affected Locations

`library/std/src/sys/pal/wasm/atomics/futex.rs:25`

## Summary

`futex_wait` converts an optional finite `Duration` into a signed nanosecond timeout for `wasm::memory_atomic_wait32`. Before the patch, a `Duration` larger than `i64::MAX` nanoseconds failed conversion and was treated the same as `None`, producing `-1`. In WebAssembly atomics, a negative timeout means wait forever, so an oversized finite timeout became an unbounded wait.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched from the provided source and patch evidence.

## Preconditions

- The target uses the wasm atomics futex implementation.
- A caller supplies `Some(Duration)` larger than `i64::MAX` nanoseconds.
- The futex contains the expected value.
- No preexisting unpark token or later wake occurs.

## Proof

The vulnerable code was:

```rust
let timeout = timeout.and_then(|t| t.as_nanos().try_into().ok()).unwrap_or(-1);
```

For `Some(t)` where `t.as_nanos()` exceeds `i64::MAX`, `try_into()` fails. `.ok()` converts the failure to `None`, and `unwrap_or(-1)` then selects `-1`.

That value is passed directly to:

```rust
wasm::memory_atomic_wait32(
    futex as *const Atomic<u32> as *mut i32,
    expected as i32,
    timeout,
)
```

`memory_atomic_wait32` treats a negative timeout as an infinite wait. Therefore a finite oversized timeout reaches the WebAssembly wait primitive as an infinite timeout.

The reproduced propagation path confirms this is reachable through public timeout APIs:

- `std::thread::park_timeout`
- `library/std/src/sys/sync/thread_parking/futex.rs:68`
- `library/std/src/sys/sync/thread_parking/futex.rs:75`
- `library/std/src/sys/pal/wasm/atomics/futex.rs:25`

## Why This Is A Real Bug

The public timeout contract requires finite timeout APIs to block for roughly no longer than the supplied duration. The previous conversion violated that contract by mapping a finite, oversized `Duration` to the sentinel for an infinite wait.

This is not only a precision or truncation issue. The control value changes semantic class from bounded to unbounded. If no wake occurs, the thread can remain blocked indefinitely.

## Fix Requirement

Overflow while converting a finite `Duration` to the wasm timeout type must not produce `-1`.

Acceptable fixes include:

- Saturating oversized finite durations to `i64::MAX`.
- Rejecting overflow in a way that does not request an infinite wait.

## Patch Rationale

The patch changes the conversion to:

```rust
let timeout = timeout.map(|t| t.as_nanos().try_into().unwrap_or(i64::MAX)).unwrap_or(-1);
```

This preserves the intended sentinel split:

- `None` still maps to `-1`, meaning infinite wait.
- `Some(duration)` maps to a non-negative timeout.
- Oversized finite durations saturate to `i64::MAX` instead of becoming infinite.

This keeps finite timeout APIs bounded and avoids introducing a new error path into the futex interface.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/pal/wasm/atomics/futex.rs b/library/std/src/sys/pal/wasm/atomics/futex.rs
index 6676aa7e8e3..c0d4eb49f5f 100644
--- a/library/std/src/sys/pal/wasm/atomics/futex.rs
+++ b/library/std/src/sys/pal/wasm/atomics/futex.rs
@@ -22,7 +22,7 @@
 ///
 /// Returns false on timeout, and true in all other cases.
 pub fn futex_wait(futex: &Atomic<u32>, expected: u32, timeout: Option<Duration>) -> bool {
-    let timeout = timeout.and_then(|t| t.as_nanos().try_into().ok()).unwrap_or(-1);
+    let timeout = timeout.map(|t| t.as_nanos().try_into().unwrap_or(i64::MAX)).unwrap_or(-1);
     unsafe {
         wasm::memory_atomic_wait32(
             futex as *const Atomic<u32> as *mut i32,
```