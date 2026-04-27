# unchecked NonZero construction

## Classification

Invariant violation, medium severity.

## Affected Locations

`library/std/src/sys/thread/hermit.rs:73`

## Summary

The Hermit implementation of `std::thread::available_parallelism()` constructed `NonZero<usize>` with `NonZero::new_unchecked` from the raw `hermit_abi::available_parallelism()` result. If the ABI returned `0`, safe callers could trigger invalid `NonZero` construction instead of receiving an error.

## Provenance

Verified by reproduction and patched from scanner finding.

Source: Swival Security Scanner, https://swival.dev

Confidence: certain.

## Preconditions

`hermit_abi::available_parallelism()` returns `0`.

## Proof

`std::thread::available_parallelism()` is a public safe API and delegates to the platform implementation.

On Hermit, `library/std/src/sys/thread/mod.rs` selects `hermit::available_parallelism`.

The Hermit implementation previously did:

```rust
unsafe { Ok(NonZero::new_unchecked(hermit_abi::available_parallelism())) }
```

`NonZero::new_unchecked` requires its argument to be non-zero. No check enforced that requirement before constructing the value.

Therefore, if `hermit_abi::available_parallelism()` returned `0`, any safe caller of `std::thread::available_parallelism()` on Hermit reached an invalid `NonZero<usize>` construction.

## Why This Is A Real Bug

`NonZero<usize>` has a validity invariant: the contained value must not be zero.

The old code allowed an unchecked external ABI value to violate that invariant. In UB-checking builds this can abort; otherwise it can create invalid safe-code-observable API state. The safe API should report an unavailable or unknown thread count as an `io::Error`, not rely on an unchecked non-zero assumption.

## Fix Requirement

Replace unchecked construction with checked construction:

```rust
NonZero::new(value).ok_or(...)
```

The function must return an error when the ABI reports `0`.

## Patch Rationale

The patch changes `available_parallelism()` to:

```rust
NonZero::new(hermit_abi::available_parallelism()).ok_or(io::Error::UNKNOWN_THREAD_COUNT)
```

This preserves the existing successful return type for non-zero CPU counts and converts the invalid zero case into the standard unknown-thread-count error. It removes the unnecessary unsafe block and enforces the `NonZero` invariant before returning.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/thread/hermit.rs b/library/std/src/sys/thread/hermit.rs
index faeaa9ae2df..550d3d4714e 100644
--- a/library/std/src/sys/thread/hermit.rs
+++ b/library/std/src/sys/thread/hermit.rs
@@ -71,7 +71,7 @@ pub fn join(self) {
 }
 
 pub fn available_parallelism() -> io::Result<NonZero<usize>> {
-    unsafe { Ok(NonZero::new_unchecked(hermit_abi::available_parallelism())) }
+    NonZero::new(hermit_abi::available_parallelism()).ok_or(io::Error::UNKNOWN_THREAD_COUNT)
 }
 
 #[inline]
```