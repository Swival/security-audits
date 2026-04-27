# positive strerror_r errors ignored

## Classification

error-handling bug, medium severity, confirmed.

## Affected Locations

`library/std/src/sys/io/error/unix.rs:177`

## Summary

`error_string` calls the POSIX/XSI `strerror_r` variant but only treats negative return values as failures. POSIX/XSI `strerror_r` reports failure by returning a nonzero error number, commonly a positive value such as `EINVAL`. As a result, positive failures are ignored and the function proceeds to convert `buf` with `CStr::from_ptr` as if the call succeeded.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- `strerror_r` returns a positive error code for the supplied errno.
- A caller formats an OS error through `std::io::Error`, reaching `sys::io::error_string`.

## Proof

The affected code calls:

```rust
if strerror_r(errno as c_int, p, buf.len()) < 0 {
    panic!("strerror_r failure");
}
```

This accepts any positive return value as success.

A reproduced host test showed that POSIX/XSI `strerror_r(999999, buf, 128)` returns `22` (`EINVAL`) while writing `"Unknown error: 999999"` to the buffer. The Rust path is publicly reachable because `std::io::Error::from_raw_os_error(code)` accepts arbitrary raw OS error codes, and Display/Debug formatting calls `sys::io::error_string(code)`.

Trigger example:

```rust
let e = std::io::Error::from_raw_os_error(999999);
println!("{e}");
```

Observed behavior:

```text
Unknown error: 999999 (os error 999999)
```

That output is produced even though the underlying `strerror_r` call returned positive `EINVAL`.

## Why This Is A Real Bug

The implementation uses the XSI/POSIX `strerror_r` signature:

```rust
fn strerror_r(errnum: c_int, buf: *mut c_char, buflen: libc::size_t) -> c_int;
```

For this API, success is `0`; failure is a nonzero error number. The current `< 0` check is incompatible with that contract and violates the function's implicit invariant that `buf` is only read after a successful `strerror_r` call.

Because arbitrary raw OS error values can be supplied through safe public Rust APIs, the failure path is reachable without unsafe caller behavior.

## Fix Requirement

Treat any nonzero `strerror_r` return value as failure, or otherwise handle the returned positive error code explicitly before reading `buf`.

## Patch Rationale

The patch changes the failure check from negative-only to nonzero:

```diff
-        if strerror_r(errno as c_int, p, buf.len()) < 0 {
+        if strerror_r(errno as c_int, p, buf.len()) != 0 {
             panic!("strerror_r failure");
         }
```

This matches the POSIX/XSI contract: `0` means success, and any nonzero return value means failure. It prevents `CStr::from_ptr` from consuming `buf` after `strerror_r` reported failure.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/io/error/unix.rs b/library/std/src/sys/io/error/unix.rs
index b10343b2752..cc4d8b000e8 100644
--- a/library/std/src/sys/io/error/unix.rs
+++ b/library/std/src/sys/io/error/unix.rs
@@ -174,7 +174,7 @@ pub fn error_string(errno: i32) -> String {
 
     let p = buf.as_mut_ptr();
     unsafe {
-        if strerror_r(errno as c_int, p, buf.len()) < 0 {
+        if strerror_r(errno as c_int, p, buf.len()) != 0 {
             panic!("strerror_r failure");
         }
 
```