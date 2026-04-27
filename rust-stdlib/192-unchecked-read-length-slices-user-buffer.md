# Unchecked SGX Read Length Slices User Buffer

## Classification

Trust-boundary violation, medium severity.

## Affected Locations

`library/std/src/sys/pal/sgx/abi/usercalls/mod.rs:25`

## Summary

The SGX usercall `read` wrapper trusted the byte count returned by the untrusted usercall provider. If `raw::read` reported success with a returned length larger than the allocated enclave-side request size, `read` sliced `userbuf[..ret_len]` without validating the length. That out-of-range slice triggers a bounds failure/abort before data is copied back, allowing a malicious or buggy provider to cause enclave denial of service.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

An untrusted SGX usercall provider returns `RESULT_SUCCESS` from `raw::read` with `ret_len > userbuf.len()`.

## Proof

`read` allocates `userbuf` with `total_len`, the saturating sum of caller-provided destination buffer lengths. It then calls:

```rust
let ret_len = raw::read(fd, userbuf.as_mut_ptr(), userbuf.len()).from_sgx_result()?;
let userbuf = &userbuf[..ret_len];
```

`raw::read` returns `ret_len` from outside the enclave. `FromSgxResult` validates only whether the result code is `RESULT_SUCCESS`; it does not validate that the returned length is within the requested buffer length.

When `ret_len > userbuf.len()`, the slice expression `&userbuf[..ret_len]` is out of range. `User<[T]>` dereferences to `UserRef<[T]>`, whose slice indexing implementation aborts on out-of-range indexes. The failure occurs before the later scatter-copy loop can clamp copy ranges.

The public SGX usercall wrapper is reachable through SGX file and standard input paths, including `FileDesc::read`, `read_vectored`, and SGX stdin `Read::read`.

## Why This Is A Real Bug

The returned byte count crosses the enclave trust boundary and is controlled by the untrusted usercall provider. A successful read result is not sufficient proof that the returned length is honest or bounded by the requested capacity. Because the unchecked length is used directly in slice indexing, an adversarial provider can deterministically trigger an enclave runtime abort/DoS by returning an excessive successful length.

## Fix Requirement

Validate the returned read length before using it for indexing. The wrapper must reject or clamp any `ret_len` greater than `userbuf.len()` so that untrusted metadata cannot create an out-of-bounds slice.

## Patch Rationale

The patch clamps the untrusted returned length to the allocated user buffer length:

```rust
let userbuf = &userbuf[..cmp::min(ret_len, userbuf.len())];
```

This preserves existing successful-read behavior for valid providers while preventing an oversized returned length from being used as a slice bound. The later scatter-copy loop already limits copying by the destination buffer sizes, so clamping at the slice boundary prevents the abort and keeps copied data within allocated capacity.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/pal/sgx/abi/usercalls/mod.rs b/library/std/src/sys/pal/sgx/abi/usercalls/mod.rs
index e413bae6ab4..87a43344d0b 100644
--- a/library/std/src/sys/pal/sgx/abi/usercalls/mod.rs
+++ b/library/std/src/sys/pal/sgx/abi/usercalls/mod.rs
@@ -21,7 +21,7 @@ pub fn read(fd: Fd, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
         let total_len = bufs.iter().fold(0usize, |sum, buf| sum.saturating_add(buf.len()));
         let mut userbuf = alloc::User::<[u8]>::uninitialized(total_len);
         let ret_len = raw::read(fd, userbuf.as_mut_ptr(), userbuf.len()).from_sgx_result()?;
-        let userbuf = &userbuf[..ret_len];
+        let userbuf = &userbuf[..cmp::min(ret_len, userbuf.len())];
         let mut index = 0;
         for buf in bufs {
             let end = cmp::min(index + buf.len(), userbuf.len());
```