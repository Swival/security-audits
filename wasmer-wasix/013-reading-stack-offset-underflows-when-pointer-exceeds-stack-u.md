# Stack Pointer Bounds Check

## Classification
- Type: invariant violation
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/wasix/src/syscalls/mod.rs:568`

## Summary
`get_memory_stack_pointer` returned the guest-controlled `__stack_pointer` without validation, and `get_memory_stack_offset` subtracted it from `stack_upper` as `u64`. When `__stack_pointer > stack_upper`, the subtraction underflowed and produced a huge offset instead of rejecting invalid stack state. On the reproduced path, that wrapped offset was passed into asyncify stack snapshot reads, which then failed out-of-bounds and caused abnormal process exit.

## Provenance
- Verified and patched from a reproduced finding
- Source: Swival Security Scanner - https://swival.dev

## Preconditions
- Guest controls `__stack_pointer` with a value above `stack_upper`

## Proof
- `get_memory_stack_pointer` read the mutable guest global `__stack_pointer` and returned it unchecked.
- `get_memory_stack_offset` computed `stack_upper - stack_pointer` without first enforcing `stack_pointer <= stack_upper`.
- With `stack_pointer > stack_upper`, `u64` subtraction wrapped, yielding a bogus large stack offset.
- The reproduced path built a `WasmPtr` from that invalid state and attempted to read `stack_offset` bytes at `lib/wasix/src/syscalls/mod.rs:961` and `lib/wasix/src/syscalls/mod.rs:967`.
- That memory read failed and returned an error, which `unwind()` converted into `Err(WasiError::Exit(Errno::Unknown.into()))` at `lib/wasix/src/syscalls/mod.rs:1127` and `lib/wasix/src/syscalls/mod.rs:1130`.

## Why This Is A Real Bug
This is a guest-triggerable violation of stack invariants on the asyncify snapshot path. The implementation trusted a mutable guest stack pointer and performed unchecked arithmetic on it. Reproduction showed practical impact: the invalid wrapped offset causes snapshot handling to fail and terminate execution abnormally. Even though reproduction did not show memory corruption, the invariant break and denial-of-service outcome are real.

## Fix Requirement
Reject stack pointers outside the valid stack interval before computing the offset, and return an error instead of allowing underflow.

## Patch Rationale
The patch adds bounds validation for the guest `__stack_pointer` against the configured stack limits before subtraction. This prevents `u64` underflow, preserves the stack layout invariant, and fails closed at the source with an explicit error rather than propagating a wrapped offset into later snapshot logic.

## Residual Risk
None

## Patch
```diff
diff --git a/lib/wasix/src/syscalls/mod.rs b/lib/wasix/src/syscalls/mod.rs
@@
-    Ok(stack_upper - stack_pointer)
+    if stack_pointer < stack_lower || stack_pointer > stack_upper {
+        return Err(WasiError::Exit(Errno::Unknown.into()));
+    }
+    Ok(stack_upper - stack_pointer)
```