# Recursive Readdir Creates Concurrent Mutable Aliases

## Classification

Memory corruption; high severity; confidence: certain.

## Affected Locations

`src/runtime/node/node_fs.rs:2362`

## Summary

Recursive async `fs.readdir(..., { recursive: true })` spawned multiple work-pool subtasks that each materialized `&mut AsyncReaddirRecursiveTask` from the same parent allocation. Sibling subtasks could run concurrently, creating overlapping mutable references and Rust undefined behavior while mutating shared parent state.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- Runtime accepts untrusted JavaScript filesystem calls.
- Attacker can invoke `fs.readdir` with `recursive: true`.
- Target directory tree contains multiple subdirectories, causing multiple recursive subtasks to be scheduled.

## Proof

A local JavaScript attacker can create or choose a directory tree with multiple subdirectories and call recursive `fs.readdir`.

The async path creates an `AsyncReaddirRecursiveTask`. During traversal, `perform_work` calls `NodeFS::readdir_with_entries_recursive_async`, which may enqueue child directories through `async_task.enqueue(...)`. Each enqueue increments `subtask_count` and schedules a work-pool `ReaddirSubtask`.

Each `ReaddirSubtask::run_owned` previously called:

```rust
unsafe { readdir_task.assume_mut() }.perform_work(...)
```

Because every sibling subtask references the same parent `AsyncReaddirRecursiveTask`, two work-pool threads could execute this conversion at the same time. That creates concurrent `&mut AsyncReaddirRecursiveTask` aliases to the same allocation.

The aliased `perform_work` path mutates shared parent fields through:
- `root_fd` assignment in recursive root handling.
- `pending_err` and `pending_err_mutex` error state.
- result aggregation via `write_results`.
- completion via `finish_concurrently`.
- queue and counter updates used to resolve the async task.

## Why This Is A Real Bug

Rust requires exclusive access for `&mut T`. The code used unsafe pointer projection to create `&mut AsyncReaddirRecursiveTask` from a shared parent reference in multiple concurrently scheduled subtasks. The work-pool scheduling and attacker-controlled directory fanout make overlapping mutable borrows reachable, not theoretical.

This is undefined behavior independent of whether a visible crash occurs. Practical outcomes include process abort, memory corruption, or incorrect async result handling.

## Fix Requirement

Parent mutation during recursive readdir must be serialized, or all shared parent state must be accessed through thread-safe interior synchronization without constructing concurrent `&mut` aliases.

## Patch Rationale

The patch serializes `perform_work` on the shared parent by adding `perform_work_mutex: bun_threading::Mutex` to `AsyncReaddirRecursiveTask`.

Both entry points that can call `perform_work` now acquire the mutex before materializing `&mut AsyncReaddirRecursiveTask`:
- `ReaddirSubtask::run_owned` locks `readdir_task.get().perform_work_mutex`.
- `AsyncReaddirRecursiveTask::work_pool_callback` avoids an early `&mut` projection, keeps the raw pointer, locks `perform_work_mutex`, then creates the mutable reference only while serialized.

This preserves the existing parent task model while restoring the exclusivity invariant required by Rust.

## Residual Risk

None

## Patch

```diff
diff --git a/src/runtime/node/node_fs.rs b/src/runtime/node/node_fs.rs
index 07cb2d7ece..1db9eeda5f 100644
--- a/src/runtime/node/node_fs.rs
+++ b/src/runtime/node/node_fs.rs
@@ -2247,6 +2247,8 @@ mod _async_tasks {
 
         pub subtask_count: AtomicUsize,
 
+        pub perform_work_mutex: bun_threading::Mutex,
+
         /// The final result list
         pub result_list: ResultListEntryValue,
 
@@ -2355,10 +2357,9 @@ mod _async_tasks {
                 }
             });
             let mut buf = PathBuffer::uninit();
-            // SAFETY: readdir_task (ParentRef) outlives subtask via subtask_count
-            // refcount. `from_raw_mut` was used at enqueue, so write provenance is
-            // present; this work-pool callback is the sole holder of `&mut` to the
-            // parent's per-result fields (it pushes to a lock-free queue).
+            let _guard = readdir_task.get().perform_work_mutex.lock_guard();
+            // SAFETY: readdir_task outlives subtask via subtask_count, and
+            // perform_work_mutex serializes mutable access to the parent.
             unsafe { readdir_task.assume_mut() }.perform_work(
                 basename.slice_assume_z(),
                 &mut buf,
@@ -2470,6 +2471,7 @@ mod _async_tasks {
                 r#ref: KeepAlive::default(),
                 tracker: AsyncTaskTracker::init(vm),
                 subtask_count: AtomicUsize::new(1),
+                perform_work_mutex: bun_threading::Mutex::default(),
                 root_path,
                 result_list,
                 result_list_count: AtomicUsize::new(0),
@@ -2550,10 +2552,11 @@ mod _async_tasks {
 
         fn work_pool_callback(task: *mut WorkPoolTask) {
             // SAFETY: task points to Self.task
-            let this = unsafe { &mut *Self::from_task_ptr(task) };
+            let this = Self::from_task_ptr(task);
             let mut buf = PathBuffer::uninit();
-            let root_path = this.root_path;
-            this.perform_work(root_path.slice_assume_z(), &mut buf, true);
+            let root_path = unsafe { (*this).root_path };
+            let _guard = unsafe { &*this }.perform_work_mutex.lock_guard();
+            unsafe { &mut *this }.perform_work(root_path.slice_assume_z(), &mut buf, true);
         }
 
         pub fn write_results<T: IntoResultListEntry>(&mut self, result: &mut Vec<T>) {
```