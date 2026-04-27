# Created Directory Handle Leak

## Classification

Resource lifecycle bug; medium severity; confidence certain.

## Affected Locations

`library/std/src/sys/fs/uefi.rs:871`

## Summary

`uefi_fs::mkdir` creates a directory by calling the private raw-handle opener `File::open` with `MODE_CREATE`, then discards the returned `NonNull<file::Protocol>`. Because the returned value is not wrapped in the RAII `uefi_fs::File`, `Drop` is bypassed and the UEFI file protocol handle is never closed.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- Caller creates a non-existing directory through UEFI `mkdir`.
- `File::open` succeeds for the target path with `MODE_READ | MODE_WRITE | MODE_CREATE`.
- Firmware/driver expects opened UEFI file protocol handles to be closed through `close`.

## Proof

In `uefi_fs::mkdir`, the successful creation path is:

```rust
let _ = File::open(
    vol,
    &mut path_remaining,
    file::MODE_READ | file::MODE_WRITE | file::MODE_CREATE,
    file::DIRECTORY,
)?;
```

The invoked function is the private `uefi_fs::File::open`, whose return type is:

```rust
io::Result<NonNull<file::Protocol>>
```

That raw `NonNull<file::Protocol>` is assigned to `_` and immediately discarded. It is not converted into:

```rust
uefi_fs::File { protocol, path }
```

The only shown close path for normal file handles is `impl Drop for File`, which calls the UEFI file protocol `close` method. Since no `File` value is constructed on the mkdir success path, that destructor never runs.

Reachability is direct through:

```rust
DirBuilder::mkdir -> uefi_fs::mkdir
```

Each successful non-existing directory creation leaks one UEFI file protocol handle.

## Why This Is A Real Bug

UEFI file protocol handles are explicit resources. Opening a file or directory produces a handle that must be closed. The surrounding implementation already encodes that invariant in `uefi_fs::File`: its `Drop` implementation closes `self.protocol`.

The buggy code bypasses that invariant by using the raw opener directly and discarding the raw handle. This is not a harmless temporary: `NonNull<file::Protocol>` has no destructor and cannot close the firmware handle on drop. Repeated successful directory creation can therefore exhaust firmware or filesystem-driver handle resources and cause later file operations to fail.

## Fix Requirement

The created protocol handle must be closed on all successful creation paths. This can be done by either:

- constructing a `uefi_fs::File` wrapper so `Drop` closes the handle, or
- explicitly invoking the UEFI file protocol `close` method before returning.

## Patch Rationale

The patch wraps the returned raw protocol handle in `uefi_fs::File`:

```rust
let _created = File {
    protocol: File::open(
        vol,
        &mut path_remaining,
        file::MODE_READ | file::MODE_WRITE | file::MODE_CREATE,
        file::DIRECTORY,
    )?,
    path: absolute,
};
```

This restores the module’s RAII invariant. `_created` lives until the end of `mkdir`; when it goes out of scope, `impl Drop for File` calls `close` on the protocol handle. Error behavior is preserved because `?` still returns the original open error before constructing the wrapper.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/fs/uefi.rs b/library/std/src/sys/fs/uefi.rs
index ef523a9807f..f9dc910eed4 100644
--- a/library/std/src/sys/fs/uefi.rs
+++ b/library/std/src/sys/fs/uefi.rs
@@ -871,12 +871,15 @@ pub(crate) fn mkdir(path: &Path) -> io::Result<()> {
             Err(e) => return Err(e),
         }
 
-        let _ = File::open(
-            vol,
-            &mut path_remaining,
-            file::MODE_READ | file::MODE_WRITE | file::MODE_CREATE,
-            file::DIRECTORY,
-        )?;
+        let _created = File {
+            protocol: File::open(
+                vol,
+                &mut path_remaining,
+                file::MODE_READ | file::MODE_WRITE | file::MODE_CREATE,
+                file::DIRECTORY,
+            )?,
+            path: absolute,
+        };
 
         Ok(())
     }
```