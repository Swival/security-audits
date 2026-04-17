# Write guard incorrectly marked `Send`

## Classification
- Type: invariant violation
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/wasix/src/utils/owned_mutex_guard.rs:155`

## Summary
`OwnedRwLockWriteGuard<T>` was manually marked `Send`, allowing safe code to move a write guard to another thread. That is unsound because the wrapped `std::sync::RwLockWriteGuard` is intentionally thread-affine and not `Send`. In the reproduced case, this also exposed `&T` on a foreign thread for `T: Send + !Sync`.

## Provenance
- Verified from the provided reproducer and source review
- Scanner: https://swival.dev

## Preconditions
- `T: Send` but `T: !Sync`
- A caller obtains `OwnedRwLockWriteGuard<T>` through the public helper
- The guard is moved to another thread before dereference or drop

## Proof
`write_owned` constructs `OwnedRwLockWriteGuard<T>` by storing a `RwLockWriteGuard<'static, T>` obtained via `transmute`. The type then declared:
```rust
unsafe impl<T> Send for OwnedRwLockWriteGuard<T> where T: Send {}
```

That lets safe code transfer the write guard across threads. On the destination thread:
- `Deref` yields `&T`
- `DerefMut` yields `&mut T`
- `Drop` releases the underlying `RwLockWriteGuard`

The reproducer confirmed this compiles and runs for a `T` that is `Send` but not `Sync`, while the equivalent program using plain `std::sync::RwLockWriteGuard` does not compile because the standard guard is `!Send`.

## Why This Is A Real Bug
This wrapper weakens a standard library safety invariant in safe code. `std::sync::RwLockWriteGuard` is non-`Send` regardless of `T`, so transferring it through a wrapper is already unsound relative to its contract. The reproduced case demonstrates a concrete consequence: safe cross-thread creation of `&T` for `T: !Sync`, plus cross-thread unlock/drop of a guard that the standard type forbids moving.

## Fix Requirement
Remove the manual `Send` impl for `OwnedRwLockWriteGuard<T>`. Tightening it to `T: Send + Sync` is insufficient because it would still permit behavior that `std::sync::RwLockWriteGuard` intentionally forbids.

## Patch Rationale
The patch deletes the `unsafe impl Send for OwnedRwLockWriteGuard<T>` from `lib/wasix/src/utils/owned_mutex_guard.rs`. This restores the wrapped guard's thread-affinity and aligns the wrapper with the standard library semantics instead of trying to re-specify them with weaker bounds.

## Residual Risk
None

## Patch
Patch file: `029-write-guard-marked-send-without-required-sync-bound.patch`

```diff
diff --git a/lib/wasix/src/utils/owned_mutex_guard.rs b/lib/wasix/src/utils/owned_mutex_guard.rs
index 0000000..0000000 100644
--- a/lib/wasix/src/utils/owned_mutex_guard.rs
+++ b/lib/wasix/src/utils/owned_mutex_guard.rs
@@ -152,7 +152,6 @@ pub struct OwnedRwLockWriteGuard<T: ?Sized + 'static> {
     guard: std::sync::RwLockWriteGuard<'static, T>,
 }
 
-unsafe impl<T> Send for OwnedRwLockWriteGuard<T> where T: Send {}
 unsafe impl<T> Sync for OwnedRwLockWriteGuard<T> where T: Send + Sync {}
 
 impl<T: ?Sized> Deref for OwnedRwLockWriteGuard<T> {
```