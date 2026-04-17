# Read guard `Send` without `Sync` bound

## Classification
- Severity: High
- Type: invariant violation
- Confidence: certain

## Affected Locations
- `lib/wasix/src/utils/owned_mutex_guard.rs:83`

## Summary
`OwnedRwLockReadGuard<T>` was manually marked `Send` for any `T: Send`, even though its `Deref` exposes `&T` after the guard is moved across threads. That permits cross-thread shared access to non-`Sync` types and breaks the thread-safety invariant normally enforced by `std::sync::RwLockReadGuard`.

## Provenance
- Verified finding reproduced from the provided report and reproducer summary
- Scanner source: https://swival.dev

## Preconditions
- `T: Send` but not `Sync`
- An `OwnedRwLockReadGuard<T>` created by `read_owned` is moved to another thread

## Proof
`read_owned` constructs `OwnedRwLockReadGuard<T>` from `RwLockReadGuard<'_, T>` by extending the guard lifetime to `'static`. The type then exposes `&T` through `Deref`. At `lib/wasix/src/utils/owned_mutex_guard.rs:83`, the code used:
```rust
unsafe impl<T> Send for OwnedRwLockReadGuard<T> where T: Send {}
```
That impl allows moving the read guard to another thread without requiring `T: Sync`. For `T = Cell<u32>`, this yields cross-thread `&Cell<u32>` access while only holding read locks, enabling unsynchronized mutation through shared references. This is exactly the class of aliasing/thread-safety violation that `Sync` bounds are meant to prevent.

## Why This Is A Real Bug
The standard library does not allow a read guard to be `Send` solely on `T: Send` because sending a guard also sends the ability to produce shared references on another thread. Shared references are only thread-safe when `T: Sync`. The current manual impl weakens that requirement and makes the abstraction unsound for any crate-internal caller using `T: Send + !Sync`. The fact that one current call site uses a `Sync` payload does not remove the generic unsoundness.

## Fix Requirement
Require `T: Sync` for the read guard's `Send` impl, or remove the unsafe `Send` impl entirely.

## Patch Rationale
The patch tightens the unsafe impl to match the actual safety requirement of cross-thread shared-reference access. Requiring `T: Sync` preserves intended owned-guard behavior for thread-safe payloads while closing the unsound generic case.

## Residual Risk
None

## Patch
```diff
--- a/lib/wasix/src/utils/owned_mutex_guard.rs
+++ b/lib/wasix/src/utils/owned_mutex_guard.rs
@@
-unsafe impl<T> Send for OwnedRwLockReadGuard<T> where T: Send {}
+unsafe impl<T> Send for OwnedRwLockReadGuard<T> where T: Sync {}
```