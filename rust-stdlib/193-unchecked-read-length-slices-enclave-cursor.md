# unchecked read length slices enclave cursor

## Classification

Validation gap, medium severity.

## Affected Locations

`library/std/src/sys/pal/sgx/abi/usercalls/mod.rs:47`

## Summary

`read_buf` trusts the byte count returned by the untrusted SGX usercall host. If the host reports success with `len > userbuf.len()`, the wrapper slices `userbuf[..len]` and `buf.as_mut()[..len]` out of bounds, causing an enclave abort.

## Provenance

Verified from supplied source and reproducer evidence. Finding provenance includes Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The SGX usercall host is untrusted.
- The host returns `RESULT_SUCCESS`.
- The returned read length is greater than the requested buffer capacity.

## Proof

`read_buf` allocates a user buffer sized to `buf.capacity()`:

```rust
let mut userbuf = alloc::User::<[u8]>::uninitialized(buf.capacity());
```

It then asks the host to read at most `userbuf.len()` bytes:

```rust
let len = raw::read(fd, userbuf.as_mut_ptr().cast(), userbuf.len()).from_sgx_result()?;
```

Before the patch, `len` was used directly for enclave and user-buffer slicing:

```rust
userbuf[..len].copy_to_enclave(&mut buf.as_mut()[..len]);
buf.advance(len);
```

If the host returns `len > userbuf.len()`, `userbuf[..len]` is out of range. The reproduced path confirms `UserRef<[T]>` indexing aborts on out-of-range slices via `rtabort!("index out of range for user slice")`.

Reachable callers include:

- `library/std/src/sys/fd/sgx.rs:31`
- `library/std/src/sys/stdio/sgx.rs:28`
- `library/std/src/sys/net/connection/sgx.rs:172`
- `library/std/src/os/fortanix_sgx/mod.rs:13`

## Why This Is A Real Bug

SGX usercalls cross the enclave trust boundary. The host controls the raw return tuple, including the reported byte count on success. The requested maximum length does not prove the returned length respects that maximum.

Because `read_buf` is a public SGX usercall wrapper and is reached by file, stdio, and network read paths, a malicious or faulty host can force enclave termination during normal read-buffer operations by returning an oversized success length.

## Fix Requirement

Reject or abort when the returned read length exceeds the allocated user buffer length before any slicing, copying, or cursor advancement occurs.

Required invariant:

```rust
len <= userbuf.len()
```

This also protects `buf.as_mut()[..len]` because `userbuf.len()` equals the original `BorrowedCursor` capacity.

## Patch Rationale

The patch adds an explicit trust-boundary validation immediately after translating the raw usercall result:

```rust
if len > userbuf.len() {
    rtabort!("Usercall read: returned invalid length {len}");
}
```

This prevents out-of-bounds slicing on both the user buffer and enclave cursor. Aborting is consistent with nearby SGX usercall validation behavior for impossible or invalid host-provided values.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/pal/sgx/abi/usercalls/mod.rs b/library/std/src/sys/pal/sgx/abi/usercalls/mod.rs
index e413bae6ab4..43ae09b3077 100644
--- a/library/std/src/sys/pal/sgx/abi/usercalls/mod.rs
+++ b/library/std/src/sys/pal/sgx/abi/usercalls/mod.rs
@@ -43,6 +43,9 @@ pub fn read_buf(fd: Fd, mut buf: BorrowedCursor<'_>) -> io::Result<()> {
     unsafe {
         let mut userbuf = alloc::User::<[u8]>::uninitialized(buf.capacity());
         let len = raw::read(fd, userbuf.as_mut_ptr().cast(), userbuf.len()).from_sgx_result()?;
+        if len > userbuf.len() {
+            rtabort!("Usercall read: returned invalid length {len}");
+        }
         userbuf[..len].copy_to_enclave(&mut buf.as_mut()[..len]);
         buf.advance(len);
         Ok(())
```