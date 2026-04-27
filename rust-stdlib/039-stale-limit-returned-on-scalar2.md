# Stale Limit Returned On Scalar2

## Classification

Logic error, medium severity. Confidence: certain.

## Affected Locations

`library/std/src/os/xous/ffi.rs:651`

## Summary

`adjust_limit()` discards the syscall output register `a2` on the successful `SyscallResult::Scalar2` path and returns the pre-call `current` value instead. This violates the function contract, which states that the adjusted value is returned after a successful limit adjustment.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- `adjust_limit(knob, current, new)` is called.
- The `AdjustProcessLimit` syscall succeeds with `SyscallResult::Scalar2`.
- The syscall leaves `a1 == knob as usize`.
- The syscall returns an adjusted limit in `a2`.
- The returned adjusted limit differs from the caller-supplied `current`.

## Proof

The wrapper initializes `a2` from `current`:

```rust
let a2 = current;
```

It then invokes the syscall using inline assembly:

```rust
inlateout("a2") a2 => _,
```

The `=> _` output operand explicitly discards the post-syscall value of register `a2`.

On success, the `Scalar2` branch returns:

```rust
Ok(a2)
```

Because the syscall output was discarded, `a2` is still the immutable pre-call `current` value. Therefore, for any successful `Scalar2` response where the kernel returns a different adjusted limit in `a2`, `adjust_limit()` returns the stale old value.

Nearby code confirms the convention that `Scalar2` carries return values in `a1` and `a2`: `blocking_scalar_impl()` returns `[a1, a2, 0, 0, 0]` for `SyscallResult::Scalar2`.

## Why This Is A Real Bug

The function documentation states that the new adjusted value is returned after a successful call. The implementation instead returns the caller-provided old value on the successful `Scalar2` path.

This can cause callers to make incorrect memory-limit or heap-accounting decisions after a limit adjustment. No current in-tree call sites were identified in the reproduced finding, but the public wrapper behavior is still incorrect and reachable under the stated syscall result.

## Fix Requirement

Capture the post-syscall value of register `a2` into a mutable local and return that captured value on the `Scalar2` success path.

## Patch Rationale

The patch changes `a2` from an immutable input-only local with discarded output into a mutable `inlateout` operand:

```rust
let mut a2 = current;
inlateout("a2") a2,
```

This preserves the syscall-returned `a2` value in the Rust local variable. The existing `Ok(a2)` branch then returns the adjusted limit instead of the stale input value.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/os/xous/ffi.rs b/library/std/src/os/xous/ffi.rs
index 9394f0a0496..1e33e4cb1ed 100644
--- a/library/std/src/os/xous/ffi.rs
+++ b/library/std/src/os/xous/ffi.rs
@@ -617,7 +617,7 @@ pub(crate) fn thread_id() -> Result<ThreadId, Error> {
 pub(crate) fn adjust_limit(knob: Limits, current: usize, new: usize) -> Result<usize, Error> {
     let mut a0 = Syscall::AdjustProcessLimit as usize;
     let mut a1 = knob as usize;
-    let a2 = current;
+    let mut a2 = current;
     let a3 = new;
     let a4 = 0;
     let a5 = 0;
@@ -629,7 +629,7 @@ pub(crate) fn adjust_limit(knob: Limits, current: usize, new: usize) -> Result<u
             "ecall",
             inlateout("a0") a0,
             inlateout("a1") a1,
-            inlateout("a2") a2 => _,
+            inlateout("a2") a2,
             inlateout("a3") a3 => _,
             inlateout("a4") a4 => _,
             inlateout("a5") a5 => _,
```