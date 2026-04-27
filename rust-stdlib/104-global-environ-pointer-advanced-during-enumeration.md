# Global Environ Pointer Advanced During Enumeration

## Classification

Data integrity bug. Severity: medium. Confidence: certain.

## Affected Locations

`library/std/src/sys/env/solid.rs:32`

## Summary

The Solid `std` environment enumeration implementation advanced the process-global `environ` symbol while iterating environment entries. After one successful enumeration, the global pointer was left at the terminating null entry, causing later environment enumeration calls to miss all entries.

## Provenance

Verified and patched from a Swival Security Scanner finding: https://swival.dev

## Preconditions

`env()` is called on Solid when the global `environ` pointer is non-null and contains at least one environment entry.

## Proof

`library/std/src/sys/env/solid.rs` declares the C global:

```rust
static mut environ: *const *const c_char;
```

Inside `env()`, the implementation reads and iterates that symbol directly:

```rust
if !environ.is_null() {
    while !(*environ).is_null() {
        if let Some(key_value) = parse(CStr::from_ptr(*environ).to_bytes()) {
            result.push(key_value);
        }
        environ = environ.add(1);
    }
}
```

The assignment `environ = environ.add(1)` mutates the process-global pointer rather than a local cursor. Once the loop completes, `environ` points at the terminating null entry.

Public reachability exists through `std::env::vars_os()` in `library/std/src/env.rs:154`, which calls `env_imp::env()`. `library/std/src/sys/env/mod.rs:38` selects this Solid implementation for `target_os = "solid_asp3"`.

A runtime reproducer against a normal C `environ` confirmed the same behavior: the first enumeration returned entries, the second enumeration returned zero entries, and the global pointer was left at the terminating null.

## Why This Is A Real Bug

Environment enumeration must snapshot entries without changing the process-global environment pointer. Mutating `environ` corrupts future reads in the same process. The bug affects public `std::env` APIs, so ordinary calls to `std::env::vars_os()` or `std::env::vars()` can cause later environment enumeration to return an empty environment.

The intended pattern is visible in the Unix implementation at `library/std/src/sys/env/unix.rs:78`, which copies the global environment pointer into a local mutable cursor and advances only that local variable.

## Fix Requirement

Copy the global `environ` pointer into a local mutable cursor before iteration, and advance only the local cursor.

## Patch Rationale

The patch adds a local shadowing binding:

```rust
let mut environ = environ;
```

This preserves the existing loop logic while changing the mutated object from the global C symbol to a local pointer variable. Enumeration still walks the same environment array, but the process-global `environ` value remains unchanged after `env()` returns.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/env/solid.rs b/library/std/src/sys/env/solid.rs
index 0ce5a22b425..8f6f55ff369 100644
--- a/library/std/src/sys/env/solid.rs
+++ b/library/std/src/sys/env/solid.rs
@@ -24,6 +24,7 @@ pub fn env() -> Env {
     unsafe {
         let _guard = env_read_lock();
         let mut result = Vec::new();
+        let mut environ = environ;
         if !environ.is_null() {
             while !(*environ).is_null() {
                 if let Some(key_value) = parse(CStr::from_ptr(*environ).to_bytes()) {
```