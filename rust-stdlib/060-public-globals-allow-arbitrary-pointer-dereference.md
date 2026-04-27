# Public Globals Allow Arbitrary Pointer Dereference

## Classification

High severity vulnerability: safe-code-triggerable arbitrary pointer dereference / undefined behavior.

## Affected Locations

`library/std/src/os/uefi/env.rs:15`

## Summary

`std::os::uefi::env::globals` was public and exposed mutable atomic globals that control UEFI state. Safe crate code could write an arbitrary pointer into `SYSTEM_TABLE`, set `BOOT_SERVICES_FLAG`, and then call the safe public API `boot_services()`. That API casts the stored pointer to `r_efi::efi::SystemTable` and dereferences it in unsafe code, causing a safe-code-triggerable arbitrary pointer dereference.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

Crate code can write to public `std::os::uefi::env::globals::SYSTEM_TABLE`.

## Proof

Before the patch, `globals` was declared as a public module:

```rust
pub mod globals {
    pub static SYSTEM_TABLE: Atomic<*mut c_void> = AtomicPtr::new(crate::ptr::null_mut());
    pub static IMAGE_HANDLE: Atomic<*mut c_void> = AtomicPtr::new(crate::ptr::null_mut());
    pub static BOOT_SERVICES_FLAG: Atomic<bool> = AtomicBool::new(false);
}
```

A safe caller could mutate these atomics:

```rust
#![feature(uefi_std)]

use std::ffi::c_void;
use std::os::uefi::env;
use std::sync::atomic::Ordering;

fn trigger() {
    env::globals::BOOT_SERVICES_FLAG.store(true, Ordering::Release);
    env::globals::SYSTEM_TABLE.store(1usize as *mut c_void, Ordering::Release);

    // Safe call reaches an unsafe dereference of address 0x1 as SystemTable.
    let _ = env::boot_services();
}
```

`boot_services()` then checks only `BOOT_SERVICES_FLAG`, loads `SYSTEM_TABLE` through `try_system_table()`, casts it to `NonNull<r_efi::efi::SystemTable>`, and dereferences it:

```rust
let system_table: NonNull<r_efi::efi::SystemTable> = try_system_table()?.cast();
let boot_services = unsafe { (*system_table.as_ptr()).boot_services };
```

## Why This Is A Real Bug

The public safe API allowed safe user code to place an invalid or attacker-controlled address into `SYSTEM_TABLE`. A subsequent safe call to `env::boot_services()` caused std unsafe code to dereference that address as a UEFI system table.

This violates Rust’s safety expectations because safe code can trigger undefined behavior or a crash. If the pointer references attacker-shaped memory, the returned Boot Services pointer can also poison later std UEFI operations that call through Boot Services function pointers.

## Fix Requirement

The UEFI globals must not be publicly mutable from safe crate code. Mutation must remain internal to std or be exposed only through validated unsafe initialization APIs that preserve the invariants required by `boot_services()`.

## Patch Rationale

The patch changes the `globals` module from public to private:

```diff
-pub mod globals {
+mod globals {
```

This prevents external safe code from accessing `SYSTEM_TABLE`, `IMAGE_HANDLE`, or `BOOT_SERVICES_FLAG` directly. The existing internal initialization path, `pub(crate) unsafe fn init_globals(...)`, remains responsible for setting these values under its documented safety contract.

## Residual Risk

None

## Patch

`060-public-globals-allow-arbitrary-pointer-dereference.patch`:

```diff
diff --git a/library/std/src/os/uefi/env.rs b/library/std/src/os/uefi/env.rs
index 82e3fc9775c..18347c1d4f6 100644
--- a/library/std/src/os/uefi/env.rs
+++ b/library/std/src/os/uefi/env.rs
@@ -8,7 +8,7 @@
 
 #[doc(hidden)]
 #[cfg(not(test))]
-pub mod globals {
+mod globals {
     use crate::ffi::c_void;
     use crate::sync::atomic::{Atomic, AtomicBool, AtomicPtr};
```