# null pointer passed to from_raw_parts

## Classification

Invariant violation, medium severity.

## Affected Locations

`library/std/src/sys/pal/sgx/libunwind_integration.rs:54`

## Summary

`__rust_print_err` accepts an extern C raw pointer from libunwind and only rejects negative lengths before constructing a Rust slice. If libunwind passes `m == NULL` with `s >= 0`, the function calls `slice::from_raw_parts` with a null pointer, violating Rust's unsafe preconditions even when `s == 0`.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The Fortanix SGX libunwind integration exports and retains `__rust_print_err` for libunwind.
- libunwind calls `__rust_print_err` with `m == NULL`.
- The length argument `s` is nonnegative, including `s == 0`.

## Proof

The affected function is:

```rust
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rust_print_err(m: *mut u8, s: i32) {
    if s < 0 {
        return;
    }
    let buf = unsafe { slice::from_raw_parts(m as *const u8, s as _) };
    if let Ok(s) = str::from_utf8(&buf[..buf.iter().position(|&b| b == 0).unwrap_or(buf.len())]) {
        eprint!("{s}");
    }
}
```

`m` enters as an unconstrained extern C raw pointer. The original guard rejects only `s < 0`, so `m == NULL` and `s == 0` or greater reaches `slice::from_raw_parts`.

Rust documents that `slice::from_raw_parts` requires its pointer argument to be non-null, and that this requirement applies even for zero-length slices. An equivalent reproducer calling the same logic with `ptr::null_mut()` and `s == 0` aborts under debug UB checks with:

```text
unsafe precondition(s) violated: slice::from_raw_parts requires the pointer to be aligned and non-null
```

The violation occurs before UTF-8 validation or printing.

## Why This Is A Real Bug

This is a real unsafe-code precondition violation at an FFI boundary. C APIs commonly represent empty buffers as `(NULL, 0)` unless a non-null pointer is explicitly required. The Rust function does not document or enforce such a requirement before passing the pointer to `slice::from_raw_parts`.

The symbol is exported with `#[unsafe(no_mangle)]` and is intentionally retained for libunwind on the Fortanix SGX target, making the path reachable through the SGX std/libunwind integration.

## Fix Requirement

Return before calling `slice::from_raw_parts` when `m.is_null()` is true.

## Patch Rationale

The patch extends the existing input validation:

```diff
-    if s < 0 {
+    if m.is_null() || s < 0 {
         return;
     }
```

This preserves the existing behavior for invalid negative lengths and adds the missing raw-pointer validation required before constructing a Rust slice. It prevents `slice::from_raw_parts` from receiving a null pointer for all nonnegative lengths, including zero.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/pal/sgx/libunwind_integration.rs b/library/std/src/sys/pal/sgx/libunwind_integration.rs
index b5419ad05de..a2dd6537646 100644
--- a/library/std/src/sys/pal/sgx/libunwind_integration.rs
+++ b/library/std/src/sys/pal/sgx/libunwind_integration.rs
@@ -48,7 +48,7 @@
 
 #[unsafe(no_mangle)]
 pub unsafe extern "C" fn __rust_print_err(m: *mut u8, s: i32) {
-    if s < 0 {
+    if m.is_null() || s < 0 {
         return;
     }
     let buf = unsafe { slice::from_raw_parts(m as *const u8, s as _) };
```