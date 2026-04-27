# resume_unwind ignores required abort

## Classification

Logic error, medium severity, certain confidence.

## Affected Locations

`library/std/src/panicking.rs:841`

## Summary

`std::panic::resume_unwind` increments the panic count but ignores the `Option<MustAbort>` returned by `panic_count::increase(false)`. When called from inside a panic hook, `increase` returns `Some(MustAbort::PanicInHook)`, which is the standard library’s signal that the process must abort. Instead, `resume_unwind` continues to `rust_panic`, allowing the resumed panic to unwind and potentially be caught.

## Provenance

Verified and patched from the provided reproduction and source analysis. Scanner provenance: [Swival Security Scanner](https://swival.dev).

## Preconditions

`resume_unwind` is called while already executing a panic hook.

## Proof

`panic_count::increase(false)` increments `GLOBAL_PANIC_COUNT`, checks `LOCAL_PANIC_COUNT`, and returns `Some(MustAbort::PanicInHook)` when the current thread is marked as executing a panic hook.

`panic_with_hook` handles this condition by printing an abort message and calling `crate::process::abort()`.

Before the patch, `resume_unwind` called:

```rust
panic_count::increase(false);
```

and ignored the return value, then proceeded to:

```rust
rust_panic(&mut RewrapBox(payload))
```

A minimal trigger is:

```rust
use std::panic::{self, catch_unwind, resume_unwind};

fn main() {
    panic::set_hook(Box::new(|_| {
        resume_unwind(Box::new("second"));
    }));

    let err = catch_unwind(|| panic!("first")).unwrap_err();
    assert_eq!(err.downcast_ref::<&str>(), Some(&"second"));
}
```

This shows that a panic resumed from inside the panic hook can unwind and be caught instead of aborting.

## Why This Is A Real Bug

The panic subsystem explicitly treats panicking inside a panic hook as abort-required state. `panic_count::increase` encodes that invariant with `MustAbort::PanicInHook`, and `panic_with_hook` enforces it immediately.

`resume_unwind` is public API and can be reached from user panic hooks. Ignoring `MustAbort::PanicInHook` violates the invariant, permits execution to continue through the panic runtime, and can leave panic accounting imbalanced because the global panic count was already incremented before the abort requirement was reported.

## Fix Requirement

`resume_unwind` must inspect the return value from `panic_count::increase(false)`. If it returns `Some(MustAbort)`, `resume_unwind` must print an appropriate abort diagnostic and terminate with `crate::process::abort()`, matching the behavior required by `panic_with_hook`.

## Patch Rationale

The patch moves the payload into a mutable `RewrapBox` before increasing the panic count, allowing the abort path to print the resumed payload without consuming it.

It adds `PanicPayload::as_str` for `RewrapBox` so the `PanicInHook` case can print string payloads without invoking arbitrary formatting code, matching the safety rationale used by `panic_with_hook`.

It then stores the result of:

```rust
panic_count::increase(false)
```

and handles both abort reasons:

- `MustAbort::PanicInHook`: prints a panic-in-hook abort message and aborts.
- `MustAbort::AlwaysAbort`: prints a resumed-panic abort message and aborts.

Only when no abort is required does execution continue to:

```rust
rust_panic(&mut payload)
```

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/panicking.rs b/library/std/src/panicking.rs
index a4a974d0447..b212be0412a 100644
--- a/library/std/src/panicking.rs
+++ b/library/std/src/panicking.rs
@@ -854,8 +854,6 @@ fn panic_with_hook(
 /// It just forwards the payload to the panic runtime.
 #[cfg_attr(panic = "immediate-abort", inline)]
 pub fn resume_unwind(payload: Box<dyn Any + Send>) -> ! {
-    panic_count::increase(false);
-
     struct RewrapBox(Box<dyn Any + Send>);
 
     unsafe impl PanicPayload for RewrapBox {
@@ -866,6 +864,16 @@ fn take_box(&mut self) -> *mut (dyn Any + Send) {
         fn get(&mut self) -> &(dyn Any + Send) {
             &*self.0
         }
+
+        fn as_str(&mut self) -> Option<&str> {
+            if let Some(&s) = self.0.downcast_ref::<&'static str>() {
+                Some(s)
+            } else if let Some(s) = self.0.downcast_ref::<String>() {
+                Some(s.as_str())
+            } else {
+                None
+            }
+        }
     }
 
     impl fmt::Display for RewrapBox {
@@ -874,7 +882,25 @@ fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
         }
     }
 
-    rust_panic(&mut RewrapBox(payload))
+    let mut payload = RewrapBox(payload);
+    let must_abort = panic_count::increase(false);
+
+    if let Some(must_abort) = must_abort {
+        match must_abort {
+            panic_count::MustAbort::PanicInHook => {
+                let message: &str = payload.as_str().unwrap_or_default();
+                rtprintpanic!(
+                    "panicked at {message}\nthread panicked while processing panic. aborting.\n"
+                );
+            }
+            panic_count::MustAbort::AlwaysAbort => {
+                rtprintpanic!("aborting due to resumed panic:\n{payload}\n");
+            }
+        }
+        crate::process::abort();
+    }
+
+    rust_panic(&mut payload)
 }
 
 /// A function with a fixed suffix (through `rustc_std_internal_symbol`)
```