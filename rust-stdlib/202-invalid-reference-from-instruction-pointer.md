# Invalid Reference From Instruction Pointer

## Classification

High severity invariant violation.

Confidence: certain.

## Affected Locations

- `library/unwind/src/unwinding.rs:84`

## Summary

`_Unwind_GetIPInfo` incorrectly dereferenced an instruction pointer after casting it to `_Unwind_Word`. Instruction pointers are code addresses, not data references, so fabricating `&u8` from the returned IP violates Rust reference validity invariants and can fault on targets where executable memory is not readable.

## Provenance

- Verified by Swival Security Scanner: https://swival.dev
- Reproduced on the Xous CC-style panic unwinder path.

## Preconditions

- Caller provides a valid unwind context.
- Caller provides a valid `ip_before_insn` output pointer.
- Execution reaches the `_Unwind_GetIPInfo` wrapper.

## Proof

`_Unwind_GetIPInfo` receives `ctx` and `ip_before_insn` at `library/unwind/src/unwinding.rs:79`.

The wrapper converts both inputs into mutable references, then calls `unwinding::abi::_Unwind_GetIPInfo(ctx, ip_before_insn)` at `library/unwind/src/unwinding.rs:84`.

The returned value is an instruction pointer. The vulnerable code casts that address to `_Unwind_Word` and then dereferences it with `&*`:

```rust
unsafe { &*(unwinding::abi::_Unwind_GetIPInfo(ctx, ip_before_insn) as _Unwind_Word) }
```

Because `_Unwind_Word` is `*const u8`, this creates a Rust reference from an arbitrary code address. Code addresses are not guaranteed to be valid `u8` data references.

The reproduced path is a normal Xous panic/unwind flow:

- `library/panic_unwind/src/gcc.rs:72` raises the exception.
- `library/std/src/sys/personality/gcc.rs:220` calls `find_eh_action`.
- That path can reach `_Unwind_GetIPInfo`.

Xous models read and execute permissions separately:

- `library/std/src/os/xous/ffi/definitions/memoryflags.rs:21`
- `library/std/src/os/xous/ffi/definitions/memoryflags.rs:29`

Therefore executable memory is not source-guaranteed to be readable. If the IP is null, the same pattern also triggers Rust's null-dereference check in debug builds.

## Why This Is A Real Bug

The ABI wrapper should return the instruction pointer value. It must not treat that value as a data address and must not create a Rust reference from it.

Even if optimized code elides an actual load, the source-level `&*` creates a reference that must satisfy Rust validity rules. An instruction pointer does not provide that guarantee. On systems with execute-only or otherwise non-readable code mappings, an actual dereference can also fault.

## Fix Requirement

Return the cast instruction pointer value directly.

Do not dereference the instruction pointer and do not create a Rust reference from it.

## Patch Rationale

The patch preserves the intended ABI value conversion while removing the invalid reference creation.

Before:

```rust
unsafe { &*(unwinding::abi::_Unwind_GetIPInfo(ctx, ip_before_insn) as _Unwind_Word) }
```

After:

```rust
unwinding::abi::_Unwind_GetIPInfo(ctx, ip_before_insn) as _Unwind_Word
```

This returns the instruction pointer as `_Unwind_Word`, matching the function signature, without reading from the instruction address.

## Residual Risk

None

## Patch

```diff
diff --git a/library/unwind/src/unwinding.rs b/library/unwind/src/unwinding.rs
index 36120bc868e..0301c438c41 100644
--- a/library/unwind/src/unwinding.rs
+++ b/library/unwind/src/unwinding.rs
@@ -81,7 +81,7 @@ pub unsafe fn _Unwind_GetIPInfo(
 ) -> _Unwind_Word {
     let ctx = unsafe { &mut *(ctx as *mut UnwindContext<'_>) };
     let ip_before_insn = unsafe { &mut *(ip_before_insn as *mut c_int) };
-    unsafe { &*(unwinding::abi::_Unwind_GetIPInfo(ctx, ip_before_insn) as _Unwind_Word) }
+    unwinding::abi::_Unwind_GetIPInfo(ctx, ip_before_insn) as _Unwind_Word
 }
 
 pub unsafe fn _Unwind_GetLanguageSpecificData(ctx: *mut _Unwind_Context) -> *mut c_void {
```