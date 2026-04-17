# Empty waiter set still reports wake

## Classification
- Type: invariant violation
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/wasix/src/syscalls/wasix/futex_wake.rs:28`
- `lib/wasix/src/syscalls/wasix/futex_wait.rs:31`

## Summary
`futex_wake` reported success even when no waiter was actually awakened. Two reachable cases triggered the false positive: an existing futex entry whose `wakers` set contained no live waiter to wake, and a full miss where no futex entry existed at all. In both cases the syscall still returned `Bool::True`, violating its documented behavior and breaking the wake-progress invariant expected by callers.

## Provenance
- Verified from the supplied reproducer and code inspection
- Patched in `067-empty-waiter-set-still-reports-wake.patch`
- Scanner reference: https://swival.dev

## Preconditions
- A futex entry exists with an empty or holey `wakers` map, or no futex entry exists for the supplied pointer
- A racing waiter can leave a `None` slot visible to `futex_wake` before the waiter future is fully armed

## Proof
- `futex_wait` inserts a futex waiter slot before a live waker is guaranteed, creating a reachable `Some(None)` state at `lib/wasix/src/syscalls/wasix/futex_wait.rs:31`.
- `futex_wake` previously treated `guard.futexes.get_mut(&pointer)` as a wake hit without proving a wake occurred at `lib/wasix/src/syscalls/wasix/futex_wake.rs:28`.
- If `first = futex.wakers.keys().next()` was absent, or `remove(&id)` returned `Some(None)`, no `wake()` call happened, yet the function still set `woken = true`, logged `wake(hit)`, wrote `Bool::True`, and returned success.
- On the miss path, no futex entry was found, but the function still returned `true`, directly contradicting the syscall comment and observable behavior.

## Why This Is A Real Bug
Callers use the returned `ret_woken` flag as a progress signal. Returning success when no thread was awakened can cause higher-level synchronization to assume forward progress, skip retries, or fail to reissue a wake. The bug is not theoretical: the waiter installation order in `futex_wait` creates a practical race where `futex_wake` can consume a non-live slot and falsely report success.

## Fix Requirement
Return `Bool::True` only after a successful `wake()` on a live waiter. If no live waiter is removable, return `Bool::False` and clean up empty futex entries so stale entries do not keep producing false hits.

## Patch Rationale
The patch changes `futex_wake` to make success contingent on an actual `wake()` call. It also removes empty futex entries when no live waiter remains, preserving the futex table invariant and aligning the syscall result with its documented semantics. This directly closes both reproduced cases: empty or holey waiter sets and total misses.

## Residual Risk
None

## Patch
```diff
diff --git a/lib/wasix/src/syscalls/wasix/futex_wake.rs b/lib/wasix/src/syscalls/wasix/futex_wake.rs
index 0000000..0000000 100644
--- a/lib/wasix/src/syscalls/wasix/futex_wake.rs
+++ b/lib/wasix/src/syscalls/wasix/futex_wake.rs
@@ -25,27 +25,38 @@ pub fn futex_wake<M: MemorySize>(
 
     let pointer = futex_ptr.offset() as u64;
     let mut guard = ctx.data().state.futexs.lock().unwrap();
-    let woken = if let Some(futex) = guard.futexes.get_mut(&pointer) {
-        let first = futex.wakers.keys().next().copied();
-        if let Some(id) = first {
-            if let Some(waker) = futex.wakers.remove(&id) {
-                if let Some(waker) = waker {
-                    waker.wake();
-                }
-            }
+    let mut should_remove = false;
+    let woken = if let Some(futex) = guard.futexes.get_mut(&pointer) {
+        let first = futex.wakers.keys().next().copied();
+        let woke = if let Some(id) = first {
+            match futex.wakers.remove(&id) {
+                Some(Some(waker)) => {
+                    waker.wake();
+                    true
+                }
+                Some(None) | None => false,
+            }
+        } else {
+            false
+        };
+
+        if futex.wakers.is_empty() {
+            should_remove = true;
         }
-        tracing::trace!("futex_wake: wake(hit)");
-        true
+
+        tracing::trace!("futex_wake: wake({})", if woke { "hit" } else { "miss" });
+        woke
     } else {
         tracing::trace!("futex_wake: wake(miss)");
-        true
+        false
     };
+
+    if should_remove {
+        guard.futexes.remove(&pointer);
+    }
+
     drop(guard);
 
     let env = ctx.data();
     let memory = unsafe { env.memory_view(&ctx) };
-
     wasi_try_mem_ok!(ret_woken.write(&memory, woken.into()));
-
     Errno::Success
 }
```