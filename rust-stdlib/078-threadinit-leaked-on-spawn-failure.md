# ThreadInit Leaked on Spawn Failure

## Classification

Resource lifecycle bug, medium severity.

## Affected Locations

`library/std/src/sys/thread/motor.rs:33`

## Summary

`Thread::new` converts `Box<ThreadInit>` into a raw pointer before calling `moto_rt::thread::spawn`. If `spawn` fails, the error path returns without reconstructing and dropping the box. This leaks `ThreadInit` and any captured data retained by the thread start closure.

## Provenance

Verified and patched finding from Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- `moto_rt::thread::spawn` returns an error after `ThreadInit` has been boxed and converted with `Box::into_raw`.

## Proof

`Thread::new` receives `Box<ThreadInit>` and converts it with:

```rust
let thread_arg = Box::into_raw(init).expose_provenance() as u64;
```

At that point, Rust no longer has an owning `Box` that will automatically drop `ThreadInit`.

The raw pointer is stored only in `thread_arg`, then passed to:

```rust
moto_rt::thread::spawn(__moto_rt_thread_fn, stack, thread_arg)
```

On success, the spawned thread reconstructs ownership in `__moto_rt_thread_fn` with `Box::from_raw`.

On failure, the previous implementation used:

```rust
.map_err(map_motor_error)?
```

That propagated the error without calling `Box::from_raw`, so the allocation was permanently leaked.

This path is reachable through public APIs: `std::thread::Builder::spawn` calls `spawn_unchecked`, which allocates `ThreadInit` in `library/std/src/thread/lifecycle.rs:100` and calls the platform thread constructor in `library/std/src/thread/lifecycle.rs:116`.

## Why This Is A Real Bug

The leak is not limited to a small fixed allocation. `ThreadInit` owns the thread initialization state, including the boxed Rust start closure. That closure can retain arbitrary user-captured data, so a spawn failure can leak user-controlled memory and resources.

For scoped threads, the failure path can also affect scope bookkeeping. `library/std/src/thread/lifecycle.rs:85` increments the running-thread count before the platform spawn call, while the decrement happens from `Packet` drop at `library/std/src/thread/lifecycle.rs:193`. Because the leaked closure can retain the child `Arc<Packet>`, the packet is not dropped, which can leave `thread::scope` waiting at `library/std/src/thread/scoped.rs:161`.

## Fix Requirement

On `moto_rt::thread::spawn` failure, reconstruct the original `Box<ThreadInit>` from `thread_arg` and drop it before returning the mapped error.

## Patch Rationale

The patch restores ownership on the error path:

```rust
drop(unsafe {
    Box::from_raw(core::ptr::with_exposed_provenance_mut::<ThreadInit>(
        thread_arg as usize,
    ))
});
```

This mirrors the success path’s pointer reconstruction in `__moto_rt_thread_fn`, but performs it only when no thread was created and therefore no spawned thread can consume `thread_arg`.

After dropping the reconstructed box, the original motor runtime error is still converted with `map_motor_error(err)` and returned unchanged.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/thread/motor.rs b/library/std/src/sys/thread/motor.rs
index c6a7b5ac356..19debde6876 100644
--- a/library/std/src/sys/thread/motor.rs
+++ b/library/std/src/sys/thread/motor.rs
@@ -30,8 +30,14 @@ extern "C" fn __moto_rt_thread_fn(thread_arg: u64) {
         }
 
         let thread_arg = Box::into_raw(init).expose_provenance() as u64;
-        let sys_thread = moto_rt::thread::spawn(__moto_rt_thread_fn, stack, thread_arg)
-            .map_err(map_motor_error)?;
+        let sys_thread = moto_rt::thread::spawn(__moto_rt_thread_fn, stack, thread_arg).map_err(|err| {
+            drop(unsafe {
+                Box::from_raw(core::ptr::with_exposed_provenance_mut::<ThreadInit>(
+                    thread_arg as usize,
+                ))
+            });
+            map_motor_error(err)
+        })?;
         Ok(Self { sys_thread })
     }
```