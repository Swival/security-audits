# Zero-length error buffer underflows truncation length

## Classification
- Severity: medium
- Type: error-handling bug
- Confidence: certain

## Affected Locations
- `lib/wasix/src/syscalls/wasix/dlopen.rs:68`

## Summary
`dlopen` error handling forwards caller-controlled `err_buf_len` into `write_dl_error`. When `err_buf_len == 0` and the error message is non-empty, truncation logic subtracts `1` from zero to reserve space for a terminator, underflowing the computed slice length and panicking before any guest-memory write occurs.

## Provenance
- Verified from the provided reproducer and source analysis in `lib/wasix/src/syscalls/wasix/dlopen.rs`
- Scanner reference: https://swival.dev

## Preconditions
- Caller passes `err_buf_len == 0` on a failing `dlopen` path

## Proof
- `dlopen` routes failures through `wasi_dl_err!` / `wasi_try_dl!`, which call `write_dl_error` with caller-supplied `err_buf_len`.
- In `write_dl_error`, truncation executes when `err.len() > err_buf_len`.
- The prior logic computes `err_len = err_buf_len as usize - 1`; with `err_buf_len == 0`, this underflows.
- The subsequent slice operation `err = &err[..err_len]` then panics due to an impossible bound.
- Reachable failing paths exist, including the immediate non-dynamic-linking error and normal module load failures in `dlopen`.

## Why This Is A Real Bug
This is externally reachable from guest input, requires no invalid memory access to trigger, and converts an expected error return into a host-side panic/trap. That is a denial-of-service condition in the syscall’s error path.

## Fix Requirement
Return early when `err_buf_len == 0` before any truncation arithmetic or terminator write.

## Patch Rationale
A zero-length error buffer cannot store payload bytes or a trailing NUL, so the only correct behavior is to skip writing entirely. Guarding this case removes the underflow and preserves existing behavior for all positive buffer lengths.

## Residual Risk
None

## Patch
```diff
diff --git a/lib/wasix/src/syscalls/wasix/dlopen.rs b/lib/wasix/src/syscalls/wasix/dlopen.rs
--- a/lib/wasix/src/syscalls/wasix/dlopen.rs
+++ b/lib/wasix/src/syscalls/wasix/dlopen.rs
@@
 fn write_dl_error<M: MemorySize>(
     mut ctx: FunctionEnvMut<'_, WasiEnv>,
     err: &str,
     err_buf: WasmPtr<u8, M>,
     err_buf_len: M::Offset,
 ) -> Result<(), Errno> {
+    if err_buf_len == M::Offset::ZERO {
+        return Ok(());
+    }
+
     let memory = unsafe { ctx.data().memory_view(&ctx) };
 
     let mut err = err.as_bytes();
     if err.len() > err_buf_len.into() {
         let err_len = err_buf_len as usize - 1;
```