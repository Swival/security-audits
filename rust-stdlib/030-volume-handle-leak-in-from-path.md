# Volume Handle Leak In `from_path`

## Classification

Resource lifecycle bug; medium severity; confidence certain.

## Affected Locations

`library/std/src/sys/fs/uefi.rs:604`

## Summary

`uefi_fs::File::from_path` opens a UEFI filesystem volume, then opens the requested child path from that volume. The returned `File` owns only the child protocol handle. The intermediate volume/root file protocol handle is not wrapped in an owning `File` and is therefore never closed.

The patch wraps the volume handle in a temporary `File` guard so normal `Drop` closes it after the child open completes or unwinds through an error.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- `File::from_path` succeeds in opening a volume through `open_volume_from_device_path`.
- The requested child path is opened from that volume.
- The caller uses any public filesystem operation that reaches `uefi_fs::File::from_path`, such as `File::open`, `readdir`, `exists`, or `stat`.

## Proof

The reproduced execution path is:

```text
public fs API
-> uefi_fs::File::from_path
-> open_volume_from_device_path
-> open_volume
-> Self::open(vol, child_path, ...)
```

Before the patch:

```rust
let (vol, mut path_remaining) = Self::open_volume_from_device_path(p.borrow())?;

let protocol = Self::open(vol, &mut path_remaining, open_mode, attr)?;
Ok(Self { protocol, path: absolute })
```

`vol` is a raw `NonNull<file::Protocol>` returned by `open_volume`. It is used to open the child protocol, but no owning `File` is created for `vol`. The returned `Self` owns only `protocol`.

`Drop for File` closes only `self.protocol`:

```rust
impl Drop for File {
    fn drop(&mut self) {
        let file_ptr = self.protocol.as_ptr();
        let _ = unsafe { ((*file_ptr).close)(file_ptr) };
    }
}
```

Therefore, every successful `from_path` call leaks the opened volume/root file protocol handle.

## Why This Is A Real Bug

UEFI file protocol handles opened through `open_volume` require a matching `close`. The code already encodes that lifecycle invariant in `Drop for File`, but `from_path` bypasses ownership for the volume handle.

This is practically reachable through public filesystem operations including:

- `File::open` at `library/std/src/sys/fs/uefi.rs:270`
- `readdir` at `library/std/src/sys/fs/uefi.rs:420`
- `exists` at `library/std/src/sys/fs/uefi.rs:510`
- `stat` at `library/std/src/sys/fs/uefi.rs:531`

A long-running UEFI process can accumulate one leaked firmware file handle per successful operation and eventually exhaust firmware file handles or associated resources.

## Fix Requirement

The volume/root file protocol handle returned by `open_volume_from_device_path` must become owned immediately after it is opened, and it must be closed on both success and error paths after the child open attempt.

## Patch Rationale

The patch converts the raw `vol` handle into a temporary `File`:

```rust
let vol = Self { protocol: vol, path: absolute.clone() };
```

The child is then opened through `vol.protocol`:

```rust
let protocol = Self::open(vol.protocol, &mut path_remaining, open_mode, attr)?;
```

This preserves existing behavior while giving the volume handle normal RAII cleanup. When `from_path` returns, the temporary `vol` is dropped and its `close` method is invoked. If `Self::open` returns an error, `vol` is also dropped during unwinding from the function, closing the volume handle on the failure path.

The returned `File` still owns only the requested child protocol handle.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/fs/uefi.rs b/library/std/src/sys/fs/uefi.rs
index ef523a9807f..d8df2b1af2d 100644
--- a/library/std/src/sys/fs/uefi.rs
+++ b/library/std/src/sys/fs/uefi.rs
@@ -599,8 +599,9 @@ pub(crate) fn from_path(path: &Path, open_mode: u64, attr: u64) -> io::Result<Se
 
             let p = helpers::OwnedDevicePath::from_text(absolute.as_os_str())?;
             let (vol, mut path_remaining) = Self::open_volume_from_device_path(p.borrow())?;
+            let vol = Self { protocol: vol, path: absolute.clone() };
 
-            let protocol = Self::open(vol, &mut path_remaining, open_mode, attr)?;
+            let protocol = Self::open(vol.protocol, &mut path_remaining, open_mode, attr)?;
             Ok(Self { protocol, path: absolute })
         }
```