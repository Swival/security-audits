# Recursive TLS Initialization Invalidates Returned Pointer

## Classification

Invariant violation, medium severity, confirmed.

## Affected Locations

`library/std/src/sys/thread_local/no_threads.rs:101`

## Summary

On no-thread targets, `LazyStorage::initialize` allowed a TLS initializer to reenter the same key before the outer initialization completed. The reentrant initialization could publish and return a pointer to an inner value, then the outer initialization would resume, drop that inner value, overwrite the storage, and return a pointer to the outer value. This invalidated the pointer previously returned by the inner access.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The target uses `library/std/src/sys/thread_local/no_threads.rs`.
- A `thread_local!` initializer reenters the same TLS key.
- The reentrant initializer returns normally.
- The inner TLS access obtains a pointer/reference before the outer initializer resumes.

## Proof

The vulnerable control flow is:

- `LazyStorage::get` calls `initialize` while `state == Initial`.
- `initialize` evaluates the user initializer before marking initialization as in progress.
- The initializer reenters the same TLS key.
- The reentrant `get` still observes `state == Initial` and recursively calls `initialize`.
- The inner initialization writes a value, sets `state == Alive`, and returns its pointer.
- The outer initialization resumes and sees `state == Alive`.
- It drops the inner value, resets the state, writes the outer value, and returns.
- The pointer returned by the inner access now refers to a dropped object and then reused storage.

The source itself documents the hazard: “The resulting pointer may not be used after reentrant initialization has occurred.” It also contains a FIXME to possibly panic on recursive initialization.

A local model of `LazyStorage` confirmed the sequence: the inner access returned a pointer, the outer initialization dropped the object at that address, and the same address was reused for the outer object.

## Why This Is A Real Bug

`LazyStorage::get` returns a raw pointer intended to identify the live TLS value. Recursive initialization violates that invariant because a pointer returned from the inner initialization can be invalidated by the still-running outer initialization. The trigger path is reachable through `thread_local!` on no-thread targets. Although safe `LocalKey::with` makes escaping the reference difficult in stable safe Rust, the storage invariant is still violated and the reentrant path exists.

## Fix Requirement

Initialization must be marked as in progress before invoking the user initializer. A reentrant access to the same key during initialization must be rejected, preferably by panicking, before it can recursively initialize and publish a pointer.

## Patch Rationale

The patch replaces the ineffective post-hoc drop-time handling with an explicit `Initializing` state:

- `initialize` first checks the current state.
- `State::Initial` is allowed to proceed.
- `State::Alive` remains unreachable for this call path.
- `State::Initializing` panics with `Attempted to recursively initialize thread-local`.
- The state is set to `Initializing` before calling the user initializer.
- A guard resets the state to `Initial` if the initializer panics.
- After a successful write, the state becomes `Alive` and the guard is forgotten.

This prevents the recursive initializer from observing `Initial`, so it cannot create and return a pointer that the outer initializer later invalidates.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/thread_local/no_threads.rs b/library/std/src/sys/thread_local/no_threads.rs
index 27a589a4a76..4c063a3979c 100644
--- a/library/std/src/sys/thread_local/no_threads.rs
+++ b/library/std/src/sys/thread_local/no_threads.rs
@@ -2,7 +2,7 @@
 //! thread locals and we can instead just use plain statics!
 
 use crate::cell::{Cell, UnsafeCell};
-use crate::mem::MaybeUninit;
+use crate::mem::{self, MaybeUninit};
 use crate::ptr;
 
 #[doc(hidden)]
@@ -54,7 +54,7 @@ unsafe impl<T> Sync for EagerStorage<T> {}
 enum State {
     Initial,
     Alive,
-    Destroying,
+    Initializing,
 }
 
 #[allow(missing_debug_implementations)]
@@ -89,28 +89,29 @@ pub fn get(&'static self, i: Option<&mut Option<T>>, f: impl FnOnce() -> T) -> *
 
     #[cold]
     fn initialize(&'static self, i: Option<&mut Option<T>>, f: impl FnOnce() -> T) -> *const T {
-        let value = i.and_then(Option::take).unwrap_or_else(f);
+        // Guard against recursive initialization.
+        match self.state.get() {
+            State::Initial => {}
+            State::Alive => unreachable!(),
+            State::Initializing => panic!("Attempted to recursively initialize thread-local"),
+        }
 
-        // Destroy the old value if it is initialized
-        // FIXME(#110897): maybe panic on recursive initialization.
-        if self.state.get() == State::Alive {
-            self.state.set(State::Destroying);
-            // Safety: we check for no initialization during drop below
-            unsafe {
-                ptr::drop_in_place(self.value.get() as *mut T);
+        struct Guard<'a>(&'a Cell<State>);
+        impl<'a> Drop for Guard<'a> {
+            fn drop(&mut self) {
+                self.0.set(State::Initial);
             }
-            self.state.set(State::Initial);
         }
 
-        // Guard against initialization during drop
-        if self.state.get() == State::Destroying {
-            panic!("Attempted to initialize thread-local while it is being dropped");
-        }
+        self.state.set(State::Initializing);
+        let guard = Guard(&self.state);
+        let value = i.and_then(Option::take).unwrap_or_else(f);
 
         unsafe {
             self.value.get().write(MaybeUninit::new(value));
         }
         self.state.set(State::Alive);
+        mem::forget(guard);
 
         self.value.get() as *const T
     }
```