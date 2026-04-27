# Existence Check Leaks Opened Handle

## Classification

Resource lifecycle bug, medium severity, confidence certain.

## Affected Locations

`library/std/src/sys/fs/uefi.rs:863`

## Summary

`uefi_fs::mkdir` opens the target path to check whether it already exists. When the open succeeds, the code returns `AlreadyExists` but discards the opened `NonNull<file::Protocol>` without closing it or wrapping it in `uefi_fs::File`. This leaks one UEFI file handle per `mkdir` call on an existing path.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

`mkdir` is called for a path that already exists.

## Proof

`DirBuilder::mkdir` delegates to `uefi_fs::mkdir(p)` in `library/std/src/sys/fs/uefi.rs`.

Inside `uefi_fs::mkdir`, the target is opened as an existence check:

```rust
match File::open(vol, &mut path_remaining, file::MODE_READ, 0) {
    Ok(_) => {
        return Err(io::Error::new(io::ErrorKind::AlreadyExists, "Path already exists"));
    }
    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
    Err(e) => return Err(e),
}
```

`File::open` returns a raw `NonNull<file::Protocol>`. On the `Ok(_)` arm, that value is ignored and no owning `uefi_fs::File` is constructed.

The only normal close path for UEFI file handles in this module is `uefi_fs::File::drop`, which calls the protocol `close` method:

```rust
impl Drop for File {
    fn drop(&mut self) {
        let file_ptr = self.protocol.as_ptr();
        let _ = unsafe { ((*file_ptr).close)(file_ptr) };
    }
}
```

Because the existence-check handle is discarded before being wrapped in `File`, `Drop` cannot run. Repeated `mkdir` or `create_dir` calls on an existing path leak one opened UEFI file protocol handle per call.

## Why This Is A Real Bug

The successful existence check creates a firmware-backed file protocol handle. The handle has an explicit close requirement, and this module relies on `uefi_fs::File` ownership plus `Drop` to satisfy that requirement. Discarding the raw `NonNull<file::Protocol>` bypasses the ownership type and leaks the handle. The path is reachable through normal directory creation APIs when the directory already exists, so repeated calls can exhaust UEFI firmware or file-system resources.

## Fix Requirement

The opened protocol returned by the existence check must be closed before returning `AlreadyExists`. This can be done by either wrapping it in `uefi_fs::File` so `Drop` runs, or by explicitly invoking the protocol `close` method.

## Patch Rationale

The patch binds the opened protocol in the `Ok` arm and immediately wraps it in `File`:

```rust
Ok(protocol) => {
    drop(File { protocol, path: absolute });
    return Err(io::Error::new(io::ErrorKind::AlreadyExists, "Path already exists"));
}
```

This preserves the existing behavior of returning `AlreadyExists`, while ensuring the successfully opened handle is owned by `uefi_fs::File` and closed via its `Drop` implementation before the function returns.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/fs/uefi.rs b/library/std/src/sys/fs/uefi.rs
index ef523a9807f..80cd4872da9 100644
--- a/library/std/src/sys/fs/uefi.rs
+++ b/library/std/src/sys/fs/uefi.rs
@@ -864,7 +864,8 @@ pub(crate) fn mkdir(path: &Path) -> io::Result<()> {
 
         // Check if file exists
         match File::open(vol, &mut path_remaining, file::MODE_READ, 0) {
-            Ok(_) => {
+            Ok(protocol) => {
+                drop(File { protocol, path: absolute });
                 return Err(io::Error::new(io::ErrorKind::AlreadyExists, "Path already exists"));
             }
             Err(e) if e.kind() == io::ErrorKind::NotFound => {}
```