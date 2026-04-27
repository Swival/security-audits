# No-Op RwLock Downgrade Leaves Writer Lock Held

## Classification

Logic error, medium severity.

## Affected Locations

`library/std/src/sys/sync/rwlock/solid.rs:84`

## Summary

On the SOLID backend, `RwLock::downgrade` was implemented as a no-op. A caller holding a write lock could downgrade through the standard-library API and receive a read guard, but the underlying SOLID reader-writer lock remained in write mode.

This violates the expected `RwLockWriteGuard::downgrade` semantics: after downgrade, other readers must be able to acquire read access concurrently.

## Provenance

Verified and reproduced from a Swival Security Scanner finding.

Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The target platform uses the SOLID ASP3 `std` synchronization backend.
- A caller acquires a SOLID-backed `RwLock` write lock through `write()` or `try_write()`.
- The caller invokes `RwLockWriteGuard::downgrade`, reaching `unsafe RwLock::downgrade`.

## Proof

`library/std/src/sys/sync/rwlock/solid.rs` implements read and write acquisition using SOLID ABI calls:

- `read()` calls `abi::rwl_loc_rdl`.
- `try_read()` calls `abi::rwl_ploc_rdl`.
- `write()` calls `abi::rwl_loc_wrl`.
- `try_write()` calls `abi::rwl_ploc_wrl`.
- `read_unlock()` and `write_unlock()` both call `abi::rwl_unl_rwl`.

Before the patch, `downgrade()` did not call any SOLID ABI function:

```rust
pub unsafe fn downgrade(&self) {
    // The SOLID platform does not support the `downgrade` operation for reader writer locks, so
    // this function is simply a no-op as only 1 reader can read: the original writer.
}
```

Therefore, after a caller acquired a write lock and downgraded it, the underlying SOLID lock was still held as a writer lock.

The reproduced behavior is:

- Thread A acquires `RwLock::write()`.
- Thread A calls `RwLockWriteGuard::downgrade`.
- Thread A receives an `RwLockReadGuard`.
- Thread B calls `read()` or `try_read()`.
- Thread B still observes the underlying writer lock and blocks or fails instead of sharing read access.

This contradicts the documented standard-library contract at `library/std/src/sync/poison/rwlock.rs:829`: after downgrading, other readers are allowed to read the protected data.

## Why This Is A Real Bug

The bug is reachable through safe standard-library APIs on the affected platform. Callers using `RwLockWriteGuard::downgrade` are entitled to rely on read-lock semantics after downgrade.

Because the implementation left the underlying lock in write mode, code could unexpectedly serialize readers, block indefinitely, or deadlock when it relied on the downgraded guard allowing concurrent readers.

The previous comment claiming “only 1 reader can read: the original writer” described the bug rather than preserving the standard `RwLock` contract.

## Fix Requirement

`downgrade()` must stop leaving the SOLID lock in writer mode.

The implementation must either:

- atomically convert the write lock to a read lock if supported by the platform, or
- release the write lock and acquire a read lock so that the returned guard corresponds to an actual underlying read lock.

## Patch Rationale

The patch implements downgrade by unlocking the current writer hold and then acquiring a reader hold on the same SOLID reader-writer lock:

```rust
pub unsafe fn downgrade(&self) {
    let rwl = self.raw();
    expect_success_aborting(unsafe { abi::rwl_unl_rwl(rwl) }, &"rwl_unl_rwl");
    expect_success(unsafe { abi::rwl_loc_rdl(rwl) }, &"rwl_loc_rdl");
}
```

This aligns the underlying SOLID lock state with the guard returned by the higher-level API. After downgrade returns, the current thread holds a real read lock, so other readers can acquire read access concurrently.

The patch uses existing ABI operations already used elsewhere in the file:

- `abi::rwl_unl_rwl` for unlocking the writer hold.
- `abi::rwl_loc_rdl` for acquiring a reader hold.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/sync/rwlock/solid.rs b/library/std/src/sys/sync/rwlock/solid.rs
index f664fef9074..c27576e6459 100644
--- a/library/std/src/sys/sync/rwlock/solid.rs
+++ b/library/std/src/sys/sync/rwlock/solid.rs
@@ -82,8 +82,9 @@ pub unsafe fn write_unlock(&self) {
 
     #[inline]
     pub unsafe fn downgrade(&self) {
-        // The SOLID platform does not support the `downgrade` operation for reader writer locks, so
-        // this function is simply a no-op as only 1 reader can read: the original writer.
+        let rwl = self.raw();
+        expect_success_aborting(unsafe { abi::rwl_unl_rwl(rwl) }, &"rwl_unl_rwl");
+        expect_success(unsafe { abi::rwl_loc_rdl(rwl) }, &"rwl_loc_rdl");
     }
 }
```