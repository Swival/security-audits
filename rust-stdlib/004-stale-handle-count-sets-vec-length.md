# stale handle count sets Vec length

## Classification

Data integrity bug, medium severity.

Confidence: certain.

## Affected Locations

`library/std/src/sys/pal/uefi/helpers.rs:84`

## Summary

`locate_handles` sizes a `Vec<r_efi::efi::Handle>` from the first `LocateHandle` call, but after the second successful call it sets the vector length using the stale first-call handle count. If the UEFI handle database shrinks between calls, fewer handles are initialized than the vector length exposes, allowing later iteration to read uninitialized handle slots.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

## Preconditions

- `EFI_BOOT_SERVICES.LocateHandle` reports a larger required byte length during the initial sizing call.
- The handle set shrinks before the second `LocateHandle` call.
- The second `LocateHandle` succeeds and updates `buf_len` to the smaller number of bytes actually written.

## Proof

`locate_handles` initializes `buf_len` with the first `LocateHandle` result, computes:

```rust
let num_of_handles = buf_len / size_of::<r_efi::efi::Handle>();
```

It allocates capacity for that count, then calls `LocateHandle` again with the same mutable `buf_len`.

On success, UEFI updates `buf_len` to the bytes actually written. The original code ignores that updated value and executes:

```rust
unsafe { buf.set_len(num_of_handles) };
```

When the second call writes fewer bytes than the first reported, only `buf_len / size_of::<Handle>()` entries are initialized, while `set_len(num_of_handles)` exposes additional uninitialized entries.

The next line consumes and iterates the exposed elements:

```rust
Ok(buf.into_iter().filter_map(|x| NonNull::new(x)).collect())
```

Callers including `open_shell`, `device_path_to_text`, `OwnedDevicePath::from_text`, and `ServiceProtocol::open` iterate these handles and may pass garbage non-null handles into `OpenProtocol`.

## Why This Is A Real Bug

`Vec::set_len` requires every element up to the new length to be initialized. The second `LocateHandle` call is the operation that initializes the buffer contents, and its updated `buf_len` is the only accurate post-call count of initialized bytes.

UEFI handle databases are mutable. A successful second `LocateHandle` with a smaller written length is a valid race outcome when handles are removed between the sizing and filling calls. The stale first-call count therefore violates Rust’s initialization invariant and can expose uninitialized memory as handles.

## Fix Requirement

After the second successful `LocateHandle` call:

- Recompute the vector length from the updated `buf_len`.
- Validate that the updated byte length is aligned to `size_of::<r_efi::efi::Handle>()`.
- Call `set_len` only with the recomputed initialized handle count.

## Patch Rationale

The patch adds an alignment assertion for the updated `buf_len` and changes `set_len` to use the second-call byte count:

```rust
assert_eq!(buf_len % size_of::<r_efi::efi::Handle>(), 0);
unsafe { buf.set_len(buf_len / size_of::<r_efi::efi::Handle>()) };
```

This preserves the existing allocation strategy while ensuring the vector length reflects the number of handles actually written by the successful `LocateHandle` call, not the stale count from the initial sizing call.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/pal/uefi/helpers.rs b/library/std/src/sys/pal/uefi/helpers.rs
index 9db72db6067..d49c82f63e3 100644
--- a/library/std/src/sys/pal/uefi/helpers.rs
+++ b/library/std/src/sys/pal/uefi/helpers.rs
@@ -81,7 +81,8 @@ fn inner(
         Ok(()) => {
             // This is safe because the call will succeed only if buf_len >= required length.
             // Also, on success, the `buf_len` is updated with the size of bufferv (in bytes) written
-            unsafe { buf.set_len(num_of_handles) };
+            assert_eq!(buf_len % size_of::<r_efi::efi::Handle>(), 0);
+            unsafe { buf.set_len(buf_len / size_of::<r_efi::efi::Handle>()) };
             Ok(buf.into_iter().filter_map(|x| NonNull::new(x)).collect())
         }
         Err(e) => Err(e),
```