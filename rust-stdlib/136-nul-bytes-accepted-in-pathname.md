# NUL Bytes Accepted in Pathname

## Classification

Validation gap. Severity: medium. Confidence: certain.

## Affected Locations

`library/std/src/os/windows/net/addr.rs:131`

## Summary

`SocketAddr::from_pathname` on Windows accepted pathname inputs containing interior NUL bytes. The documented contract says such paths must return an error, but `from_pathname` forwarded the path to `sockaddr_un`, which only validated UTF-8 and length before copying bytes into `sun_path`.

Because `sun_path` is consumed as a C-style NUL-terminated path by downstream socket APIs, an input such as `"/a\0b"` could be accepted as `Ok(SocketAddr)` while consumers observe the truncated path `"/a"`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- Caller passes a UTF-8 pathname containing an interior NUL byte.
- The pathname is short enough to fit in `sun_path`.

## Proof

The vulnerable flow is:

- `SocketAddr::from_pathname` calls `sockaddr_un(path.as_ref())`.
- `sockaddr_un` converts the path to UTF-8 bytes with `to_str().as_bytes()`.
- It checks only `bytes.len() >= addr.sun_path.len()`.
- It then copies all bytes into `addr.sun_path`.
- It returns `Ok((addr, len))`.

This allowed `"/a\0b"` to reach `Ok(SocketAddr)`.

This contradicts the documented contract in `library/std/src/os/windows/net/addr.rs`, which states that `SocketAddr::from_pathname` returns an error if the path contains NULL bytes, and includes an example expecting:

```rust
assert!(SocketAddr::from_pathname("/path/with/\0/bytes").is_err());
```

The malformed address is reachable through real socket APIs:

- `UnixListener::bind` constructs a `SocketAddr` and passes the resulting `SOCKADDR_UN` to `bind`.
- `UnixStream::connect` constructs a `SocketAddr` and passes the resulting `SOCKADDR_UN` to `connect`.

The Unix implementation already performs the missing validation with `bytes.contains(&0)`, confirming the Windows path was inconsistent.

## Why This Is A Real Bug

Interior NUL bytes change how C-style pathname buffers are interpreted. Although Rust code may treat the byte string as containing `"/a\0b"`, C consumers of `sun_path` may stop at the first NUL and observe only `"/a"`.

That can cause socket misaddressing: code intending to bind or connect to one pathname may instead operate on a different truncated pathname.

The behavior also directly violates the public API documentation, which promises rejection of paths containing NULL bytes.

## Fix Requirement

Reject pathname byte sequences containing `0` before copying them into `SOCKADDR_UN.sun_path`.

## Patch Rationale

The patch adds an explicit NUL-byte validation after the existing length check and before `ptr::copy_nonoverlapping`.

This is the correct location because:

- The path has already been converted to UTF-8 bytes.
- The validated byte slice is exactly what would be copied into `sun_path`.
- Returning `InvalidInput` matches the existing error style for invalid pathname inputs.
- The behavior aligns Windows with the Unix implementation and with the documented API contract.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/os/windows/net/addr.rs b/library/std/src/os/windows/net/addr.rs
index ef2263edcf6..c008c3852ae 100644
--- a/library/std/src/os/windows/net/addr.rs
+++ b/library/std/src/os/windows/net/addr.rs
@@ -21,6 +21,9 @@ pub fn sockaddr_un(path: &Path) -> io::Result<(SOCKADDR_UN, usize)> {
     if bytes.len() >= addr.sun_path.len() {
         return Err(io::const_error!(io::ErrorKind::InvalidInput, "path too long"));
     }
+    if bytes.contains(&0) {
+        return Err(io::const_error!(io::ErrorKind::InvalidInput, "path contains null byte"));
+    }
     // SAFETY: `bytes` and `addr.sun_path` are not overlapping and
     // both point to valid memory.
     // NOTE: We zeroed the memory above, so the path is already null
```