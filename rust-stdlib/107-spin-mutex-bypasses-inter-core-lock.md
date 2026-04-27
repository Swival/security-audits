# Spin Mutex Bypasses Inter-Core Lock

## Classification

Race condition, high severity, confirmed.

## Affected Locations

`library/std/src/sys/pal/itron/spin.rs:33`

## Summary

`SpinMutex::with_locked` skips the atomic spinlock whenever dispatching is already disabled. This bypasses the inter-core exclusion mechanism while still returning `&mut T`, allowing concurrent mutable access from another core.

The patch makes atomic spinlock acquisition unconditional and only makes dispatch disable/enable conditional on the prior dispatch state.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- A caller invokes `SpinMutex::with_locked`.
- Dispatching is already disabled before entry, so `abi::sns_dsp()` returns nonzero.
- Another core can enter the same `SpinMutex`-protected critical section concurrently.

## Proof

In the vulnerable implementation, `with_locked` checks `abi::sns_dsp()` before taking the lock:

```rust
let _guard;
if unsafe { abi::sns_dsp() } == 0 {
    let er = unsafe { abi::dis_dsp() };
    debug_assert!(er >= 0);

    while self.locked.swap(true, Ordering::Acquire) {}

    _guard = SpinMutexGuard(&self.locked);
}

f(unsafe { &mut *self.data.get() })
```

When dispatching is already disabled, the condition is false. Execution therefore:

- Does not call `abi::dis_dsp()`.
- Does not execute `self.locked.swap(true, Ordering::Acquire)`.
- Does not construct `SpinMutexGuard`.
- Still calls `f(unsafe { &mut *self.data.get() })`.

This grants mutable access to the protected data without acquiring the inter-core spinlock.

A practical race follows directly: one core can enter `with_locked` while dispatching is disabled and mutate protected state without setting `locked`; another core can acquire the spinlock normally, or also bypass it, and mutate the same state concurrently.

Reachable callers include `SpinIdOnceCell::initialize`, and the same pattern affects synchronization paths such as condition-variable wait queue mutation.

## Why This Is A Real Bug

`SpinMutex` is documented as using two mechanisms:

- `dis_dsp` for intra-core synchronization.
- An atomic spinlock for inter-core synchronization.

The vulnerable implementation ties both mechanisms to the dispatch state. If dispatching is already disabled, it skips both intra-core dispatch control and the inter-core atomic lock.

That violates the mutex invariant: dispatch state on the current core does not exclude execution on other cores.

For `SpinIdOnceCell`, two cores can both observe `ID_UNINIT`, both initialize backing kernel object IDs, and then leak, overwrite, or inconsistently use those IDs. For condition-variable waiter queues, concurrent raw-pointer list mutation can corrupt queue invariants.

## Fix Requirement

`SpinMutex::with_locked` must always acquire the atomic spinlock before exposing `&mut T`.

Only dispatch control should be conditional:

- If dispatching was enabled on entry, disable it and re-enable it on drop.
- If dispatching was already disabled on entry, leave it disabled on drop.
- In both cases, acquire and release `self.locked`.

## Patch Rationale

The patch records whether dispatching was enabled on entry:

```rust
let dsp_enabled = unsafe { abi::sns_dsp() } == 0;
```

It disables dispatching only when needed:

```rust
if dsp_enabled {
    let er = unsafe { abi::dis_dsp() };
    debug_assert!(er >= 0);
}
```

It then always acquires the inter-core spinlock:

```rust
while self.locked.swap(true, Ordering::Acquire) {}
```

The guard now stores whether it should re-enable dispatching:

```rust
struct SpinMutexGuard<'a>(&'a Atomic<bool>, bool);
```

On drop, it always releases the atomic lock, but only calls `ena_dsp` when this invocation disabled dispatching:

```rust
self.0.store(false, Ordering::Release);
if self.1 {
    unsafe { abi::ena_dsp() };
}
```

This restores the intended separation between inter-core locking and dispatch-state management.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/pal/itron/spin.rs b/library/std/src/sys/pal/itron/spin.rs
index bc4f83260bb..4bc1f7f954a 100644
--- a/library/std/src/sys/pal/itron/spin.rs
+++ b/library/std/src/sys/pal/itron/spin.rs
@@ -19,27 +19,29 @@ pub const fn new(x: T) -> Self {
     /// Acquire a lock.
     #[inline]
     pub fn with_locked<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
-        struct SpinMutexGuard<'a>(&'a Atomic<bool>);
+        struct SpinMutexGuard<'a>(&'a Atomic<bool>, bool);
 
         impl Drop for SpinMutexGuard<'_> {
             #[inline]
             fn drop(&mut self) {
                 self.0.store(false, Ordering::Release);
-                unsafe { abi::ena_dsp() };
+                if self.1 {
+                    unsafe { abi::ena_dsp() };
+                }
             }
         }
 
-        let _guard;
-        if unsafe { abi::sns_dsp() } == 0 {
+        let dsp_enabled = unsafe { abi::sns_dsp() } == 0;
+        if dsp_enabled {
             let er = unsafe { abi::dis_dsp() };
             debug_assert!(er >= 0);
-
-            // Wait until the current processor acquires a lock.
-            while self.locked.swap(true, Ordering::Acquire) {}
-
-            _guard = SpinMutexGuard(&self.locked);
         }
 
+        // Wait until the current processor acquires a lock.
+        while self.locked.swap(true, Ordering::Acquire) {}
+
+        let _guard = SpinMutexGuard(&self.locked, dsp_enabled);
+
         f(unsafe { &mut *self.data.get() })
     }
 }
```