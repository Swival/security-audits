# task creation failure leaks thread state

## Classification

Resource lifecycle bug, medium severity, confirmed.

## Affected Locations

`library/std/src/sys/thread/solid.rs:184`

## Summary

`Thread::new` allocates `ThreadInner`, converts it to raw ownership, and then calls `acre_tsk`. If `acre_tsk` returns a negative error, the error path returns immediately and leaves the raw `ThreadInner` allocation unreclaimed. The leaked state includes the `ManuallyDrop<Box<ThreadInit>>`, so the thread initialization closure and captured resources also remain allocated.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

`acre_tsk` returns a negative error after `ThreadInner` is allocated and converted with `Box::into_raw`.

## Proof

`Thread::new` creates:

```rust
let inner = Box::new(ThreadInner {
    init: UnsafeCell::new(ManuallyDrop::new(init)),
    lifecycle: AtomicUsize::new(LIFECYCLE_INIT),
});
```

It then transfers ownership out of Rust’s automatic drop path:

```rust
let p_inner = unsafe { NonNull::new_unchecked(Box::into_raw(inner)) };
```

After that, task creation is attempted:

```rust
let new_task = ItronError::err_if_negative(unsafe {
    abi::acre_tsk(&abi::T_CTSK { ... })
})
.map_err(|e| e.as_io_error())?;
```

If `acre_tsk` fails, `?` returns before any `Box::from_raw(p_inner.as_ptr())` or equivalent cleanup occurs. Since no `Thread` is constructed, `Thread::drop` cannot run. Each failed creation therefore permanently leaks `ThreadInner`.

The leak also retains `ThreadInner::init`, which is a `ManuallyDrop<Box<ThreadInit>>`; because it is manually dropped, reclaiming only the outer allocation is insufficient unless the contained `ThreadInit` is explicitly dropped first.

## Why This Is A Real Bug

The ownership transfer via `Box::into_raw` removes automatic cleanup. On the `acre_tsk` error path, no owner exists for `p_inner`, and no task exists that could run `trampoline` and take `init`. The function exits with an error while retaining both the outer `ThreadInner` allocation and the inner `ThreadInit` allocation.

This is not a benign temporary allocation: repeated task creation failures produce unbounded permanent memory/resource retention. Captured resources inside the thread start closure can also be retained.

## Fix Requirement

On `acre_tsk` failure, `Thread::new` must reclaim `p_inner` before returning the converted I/O error. Because `ThreadInner::init` contains `ManuallyDrop<Box<ThreadInit>>`, the fix must explicitly drop `init` before freeing `ThreadInner`.

## Patch Rationale

The patch replaces the direct `?` return with an explicit `match` on `ItronError::err_if_negative`.

On success, behavior is unchanged: the task ID is stored in `Thread`.

On failure, the patch:

- Reborrows the raw `ThreadInner`.
- Explicitly drops `ThreadInner::init` with `ManuallyDrop::drop`.
- Reclaims the outer allocation with `Box::from_raw`.
- Returns the same `io::Error` as before.

This is safe because `acre_tsk` failed, so the task was not created and `trampoline` cannot race to take or use `init`.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/thread/solid.rs b/library/std/src/sys/thread/solid.rs
index 5953c0e7b61..286763be6c0 100644
--- a/library/std/src/sys/thread/solid.rs
+++ b/library/std/src/sys/thread/solid.rs
@@ -172,7 +172,7 @@ pub unsafe fn new(stack: usize, init: Box<ThreadInit>) -> io::Result<Thread> {
         // Safety: `Box::into_raw` returns a non-null pointer
         let p_inner = unsafe { NonNull::new_unchecked(Box::into_raw(inner)) };
 
-        let new_task = ItronError::err_if_negative(unsafe {
+        let new_task = match ItronError::err_if_negative(unsafe {
             abi::acre_tsk(&abi::T_CTSK {
                 // Activate this task immediately
                 tskatr: abi::TA_ACT,
@@ -185,8 +185,17 @@ pub unsafe fn new(stack: usize, init: Box<ThreadInit>) -> io::Result<Thread> {
                 // Let the kernel allocate the stack,
                 stk: crate::ptr::null_mut(),
             })
-        })
-        .map_err(|e| e.as_io_error())?;
+        }) {
+            Ok(task) => task,
+            Err(e) => {
+                let inner = unsafe { &mut *p_inner.as_ptr() };
+                // Safety: The task was not created, so `trampoline` cannot take `init`.
+                unsafe { ManuallyDrop::drop(&mut *inner.init.get()) };
+                // Safety: Reclaim the `ThreadInner` allocated above.
+                let _ = unsafe { Box::from_raw(p_inner.as_ptr()) };
+                return Err(e.as_io_error());
+            }
+        };
 
         Ok(Self { p_inner, task: new_task })
     }
```