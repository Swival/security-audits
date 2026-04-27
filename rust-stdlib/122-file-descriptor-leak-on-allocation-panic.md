# File Descriptor Leak On Allocation Panic

## Classification

Resource lifecycle bug, low severity.

## Affected Locations

- `library/std_detect/src/detect/os/linux/mod.rs:21`

## Summary

`read_file` opens a Linux proc/auxvec-style file with `libc::open`, then calls `Vec::reserve(4096)` before any cleanup guard owns the descriptor. If `reserve` panics after the open succeeds, unwinding skips both explicit `libc::close` calls and leaks the file descriptor.

The patch wraps the descriptor in a local RAII `FileDesc` guard whose `Drop` implementation closes the descriptor on every exit path, including unwinding.

## Provenance

- Verified by source review and reproduced under the stated panic precondition.
- Finding originated from Swival Security Scanner: https://swival.dev
- Confidence: certain.

## Preconditions

- `read_file` opens the target file successfully.
- `Vec::reserve(4096)` panics after the descriptor is opened.
- The panic is caught or otherwise the process continues after unwinding.

## Proof

In the affected implementation:

- `orig_path` is converted to a nul-terminated C path.
- `libc::open` is called and returns a valid file descriptor.
- The descriptor is stored as a raw `libc::c_int`.
- The read loop calls `data.reserve(4096)` before any guard or `Drop` wrapper exists.
- If `reserve` unwinds, execution skips the later explicit `libc::close(file)` calls.
- The descriptor remains live until process exit.

Reachability is source-grounded: Linux feature detection can call `read_file` through auxvec fallback logic for `/proc/self/auxv`-style files.

## Why This Is A Real Bug

The descriptor lifetime is manually managed with explicit `close` calls. Manual cleanup is not unwind-safe when panicking operations occur between acquisition and cleanup.

`Vec::reserve` can panic in unwind-capable configurations, including allocation-error paths where the allocation error hook panics instead of aborting. If the process catches the panic and continues, the opened descriptor is leaked. Repeated triggers can consume the process file descriptor limit.

With default aborting OOM behavior the leak is not observable because the process exits, but the stated unwinding precondition makes the bug real.

## Fix Requirement

The file descriptor must be owned by an RAII guard immediately after a successful `libc::open`, before any operation that can panic. The guard must close the descriptor in `Drop` so cleanup happens on normal return, error return, and unwinding.

## Patch Rationale

The patch introduces:

```rust
struct FileDesc(libc::c_int);

impl Drop for FileDesc {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}
```

After `libc::open` succeeds, the raw descriptor is immediately wrapped:

```rust
let file = FileDesc(file);
```

All reads use `file.0`, and the explicit close calls are removed. This makes descriptor cleanup automatic and prevents leaks from `Vec::reserve` panics or any later unwinding path.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std_detect/src/detect/os/linux/mod.rs b/library/std_detect/src/detect/os/linux/mod.rs
index aec94f963f5..403790e9be8 100644
--- a/library/std_detect/src/detect/os/linux/mod.rs
+++ b/library/std_detect/src/detect/os/linux/mod.rs
@@ -10,19 +10,29 @@ fn read_file(orig_path: &str) -> Result<Vec<u8>, alloc::string::String> {
     let mut path = Vec::from(orig_path.as_bytes());
     path.push(0);
 
+    struct FileDesc(libc::c_int);
+
+    impl Drop for FileDesc {
+        fn drop(&mut self) {
+            unsafe {
+                libc::close(self.0);
+            }
+        }
+    }
+
     unsafe {
         let file = libc::open(path.as_ptr() as *const libc::c_char, libc::O_RDONLY);
         if file == -1 {
             return Err(format!("Cannot open file at {orig_path}"));
         }
+        let file = FileDesc(file);
 
         let mut data = Vec::new();
         loop {
             data.reserve(4096);
             let spare = data.spare_capacity_mut();
-            match libc::read(file, spare.as_mut_ptr() as *mut _, spare.len()) {
+            match libc::read(file.0, spare.as_mut_ptr() as *mut _, spare.len()) {
                 -1 => {
-                    libc::close(file);
                     return Err(format!("Error while reading from file at {orig_path}"));
                 }
                 0 => break,
@@ -30,7 +40,6 @@ fn read_file(orig_path: &str) -> Result<Vec<u8>, alloc::string::String> {
             }
         }
 
-        libc::close(file);
         Ok(data)
     }
 }
```