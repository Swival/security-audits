# write downgrade skips poison finalization

## Classification

Data integrity bug; medium severity; confidence certain.

## Affected Locations

`library/std/src/sync/poison/rwlock.rs:874`

## Summary

`RwLockWriteGuard::downgrade` consumes a write guard, calls `forget(s)`, and returns a read guard. Because `forget(s)` suppresses `RwLockWriteGuard::drop`, the write guard's poison finalization path is skipped. If downgrade occurs while the thread is already panicking, the lock remains unpoisoned even though a panic occurred while exclusive write access was held.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

A write guard is downgraded while the thread is already panicking.

## Proof

The write guard owns exclusive access when passed to `RwLockWriteGuard::downgrade`.

Current downgrade flow:

```rust
pub fn downgrade(s: Self) -> RwLockReadGuard<'rwlock, T> {
    let lock = s.lock;

    // We don't want to call the destructor since that calls `write_unlock`.
    forget(s);

    unsafe { lock.inner.downgrade() };
    unsafe { RwLockReadGuard::new(lock).unwrap_or_else(PoisonError::into_inner) }
}
```

`forget(s)` skips `RwLockWriteGuard::drop`, which is the normal path that calls:

```rust
self.lock.poison.done(&self.poison);
```

The returned `RwLockReadGuard` later only performs `read_unlock`; it has no poison guard and cannot finalize write poisoning.

A local PoC confirmed the behavior:

```text
drop: thread::panicking() = true
drop: downgraded and dropping read guard
is_poisoned after unwind: false
subsequent write(): Ok
```

This shows the write section unwound during panic while holding exclusive access, but the lock remained unpoisoned.

## Why This Is A Real Bug

`RwLock` poisoning is intended to mark the lock poisoned when a writer panics while holding exclusive access. The poison flag is finalized by `poison.done` when the write guard is dropped. `downgrade` explicitly bypasses that destructor with `forget(s)`, so it must perform equivalent poison finalization before suppressing the destructor. Without that, `is_poisoned()` and subsequent `write()` calls report a clean lock after a panicking write section.

## Fix Requirement

Call `lock.poison.done(&s.poison)` before `forget(s)` and before downgrading the underlying lock.

## Patch Rationale

The patch preserves the existing downgrade behavior while restoring the missing side effect of `RwLockWriteGuard::drop`. Calling `poison.done` before `forget(s)` records poisoning if the guard was created before the current panic and the current thread is panicking. `forget(s)` can still be used to avoid `write_unlock`, allowing the atomic write-to-read downgrade to proceed normally.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sync/poison/rwlock.rs b/library/std/src/sync/poison/rwlock.rs
index 4cfd9d19df7..c2fec33b59c 100644
--- a/library/std/src/sync/poison/rwlock.rs
+++ b/library/std/src/sync/poison/rwlock.rs
@@ -882,6 +882,7 @@ unsafe fn new(lock: &'rwlock RwLock<T>) -> LockResult<RwLockWriteGuard<'rwlock,
     #[stable(feature = "rwlock_downgrade", since = "1.92.0")]
     pub fn downgrade(s: Self) -> RwLockReadGuard<'rwlock, T> {
         let lock = s.lock;
+        lock.poison.done(&s.poison);
 
         // We don't want to call the destructor since that calls `write_unlock`.
         forget(s);
```