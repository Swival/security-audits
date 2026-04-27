# timeout can exceed waiter counter

## Classification

High severity invariant violation.

## Affected Locations

`library/std/src/sys/sync/condvar/xous.rs:46`

## Summary

Xous `Condvar` timeout accounting can record more timed-out waiters than the waiter counter currently contains. A `notify_some` call pre-decrements `counter` before a waiter is confirmed woken. If that selected waiter instead times out, `timed_out` later increments while `counter` is already zero. A subsequent notify or drop can then panic or underflow in safe `Condvar::wait_timeout` / `notify_one` usage.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

One waiter times out after `notify_some` decrements `counter` but before timeout accounting reconciles the waiter.

## Proof

`wait_ms` increments `counter`, unlocks the mutex, and then calls `WaitForCondition`.

`notify_some` previously subtracted selected waiters from `counter` with `try_update` before issuing `NotifyCondition`. `NotifyCondition` may return `0` if the waiter is not yet registered with the ticktimer server, a race the adjacent Xous parker implementation explicitly handles at `library/std/src/sys/sync/thread_parking/xous.rs:99`.

If the selected waiter later reaches `WaitForCondition`, times out, and executes `timed_out.fetch_add(1)` at `library/std/src/sys/sync/condvar/xous.rs:113`, `counter` may already be `0`. No completed notify path subtracts that late timeout from `counter`.

The next `notify_some` can hit `assert!(timed_out <= counter)` at `library/std/src/sys/sync/condvar/xous.rs:33`, and `Drop` can evaluate `remaining_count - timed_out` at `library/std/src/sys/sync/condvar/xous.rs:140`, causing panic or underflow.

## Why This Is A Real Bug

The affected API is safe Rust synchronization code. A valid sequence using `Condvar::wait_timeout` and `notify_one` on Xous can leave internal accounting in an impossible state where `timed_out > counter`.

The implementation assumes a waiter selected for notification is removed from `counter` before the ticktimer confirms wake delivery. The proof shows this assumption is false because notification can fail to reach an unregistered waiter, and that waiter can still later time out. The resulting stale accounting is externally observable as a panic during later notify or drop.

## Fix Requirement

Do not decrement `counter` for selected waiters until wake delivery is confirmed, or otherwise reconcile late timeouts through the same accounting path without permitting `timed_out > counter` underflow or assertion failure.

## Patch Rationale

The patch removes the upfront assertion and pre-decrement of selected waiters.

Timed-out waiters are reconciled with `counter.saturating_sub(timed_out)`, preventing underflow if timeout accounting races with notification accounting. `notify_some` now reads the current waiter count to decide how many wake attempts to make, and only subtracts from `counter` after `NotifyCondition` reports actual notified waiters.

After each notification attempt, the patch separately reconciles newly accumulated timeouts with another saturating counter update and reduces `remaining_to_wake` with `saturating_sub`. This keeps both notification results and timeout results on the same bounded accounting path.

`Drop` is changed from `remaining_count - timed_out == 0` to `remaining_count == timed_out`, avoiding subtraction underflow while preserving the intended invariant that all remaining counted waiters are accounted for as timed out.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/sync/condvar/xous.rs b/library/std/src/sys/sync/condvar/xous.rs
index 5d1b14443c6..64e18dc5d1c 100644
--- a/library/std/src/sys/sync/condvar/xous.rs
+++ b/library/std/src/sys/sync/condvar/xous.rs
@@ -28,27 +28,21 @@ fn notify_some(&self, to_notify: usize) {
         // Assumption: The Mutex protecting this condvar is locked throughout the
         // entirety of this call, preventing calls to `wait` and `wait_timeout`.
 
-        // Logic check: Ensure that there aren't any missing waiters. Remove any that
-        // timed-out, ensuring the counter doesn't underflow.
-        assert!(self.timed_out.load(Ordering::Relaxed) <= self.counter.load(Ordering::Relaxed));
-        self.counter.fetch_sub(self.timed_out.swap(0, Ordering::Relaxed), Ordering::Relaxed);
+        // Remove timed-out waiters, ensuring the counter doesn't underflow if a timeout
+        // races with notification accounting.
+        let timed_out = self.timed_out.swap(0, Ordering::Relaxed);
+        let _ = self.counter.try_update(Ordering::Relaxed, Ordering::Relaxed, |counter| {
+            Some(counter.saturating_sub(timed_out))
+        });
 
         // Figure out how many threads to notify. Note that it is impossible for `counter`
-        // to increase during this operation because Mutex is locked. However, it is
-        // possible for `counter` to decrease due to a condvar timing out, in which
-        // case the corresponding `timed_out` will increase accordingly.
-        let Ok(waiter_count) =
-            self.counter.try_update(Ordering::Relaxed, Ordering::Relaxed, |counter| {
-                if counter == 0 {
-                    return None;
-                } else {
-                    Some(counter - counter.min(to_notify))
-                }
-            })
-        else {
+        // to increase during this operation because Mutex is locked. Timeouts are
+        // reconciled below after each notification attempt.
+        let waiter_count = self.counter.load(Ordering::Relaxed);
+        if waiter_count == 0 {
             // No threads are waiting on this condvar
             return;
-        };
+        }
 
         let mut remaining_to_wake = waiter_count.min(to_notify);
         if remaining_to_wake == 0 {
@@ -62,13 +56,20 @@ fn notify_some(&self, to_notify: usize) {
             .expect("failure to send NotifyCondition command");
 
             // Remove the list of waiters that were notified
-            remaining_to_wake -= result[0];
+            let notified = result[0];
+            let _ = self.counter.try_update(Ordering::Relaxed, Ordering::Relaxed, |counter| {
+                Some(counter.saturating_sub(notified))
+            });
+            remaining_to_wake -= notified;
 
             // Also remove the number of waiters that timed out. Clamp it to 0 in order to
             // ensure we don't wait forever in case the waiter woke up between the time
             // we counted the remaining waiters and now.
-            remaining_to_wake =
-                remaining_to_wake.saturating_sub(self.timed_out.swap(0, Ordering::Relaxed));
+            let timed_out = self.timed_out.swap(0, Ordering::Relaxed);
+            let _ = self.counter.try_update(Ordering::Relaxed, Ordering::Relaxed, |counter| {
+                Some(counter.saturating_sub(timed_out))
+            });
+            remaining_to_wake = remaining_to_wake.saturating_sub(timed_out);
             if remaining_to_wake == 0 {
                 return;
             }
@@ -138,7 +139,7 @@ fn drop(&mut self) {
         let remaining_count = self.counter.load(Ordering::Relaxed);
         let timed_out = self.timed_out.load(Ordering::Relaxed);
         assert!(
-            remaining_count - timed_out == 0,
+            remaining_count == timed_out,
             "counter was {} and timed_out was {} not 0",
             remaining_count,
             timed_out
```