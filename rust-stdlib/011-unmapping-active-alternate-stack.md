# Unmapping Active Alternate Stack

## Classification

Resource lifecycle bug; medium severity; confidence certain.

## Affected Locations

`library/std/src/sys/pal/unix/stack_overflow.rs:300`

## Summary

`drop_handler` disables the current alternate signal stack with `sigaltstack(SS_DISABLE)` and then unconditionally unmaps the backing memory. If `sigaltstack` fails because the alternate stack is active, the kernel still references that stack while Rust frees its mapping, leaving an active per-thread altstack pointing at unmapped memory.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

`sigaltstack(SS_DISABLE)` fails while `data` points to an installed alternate signal stack.

## Proof

`data` originates from `get_stack()` as `stack.ss_sp` and is stored in `Handler.data` or `MAIN_ALTSTACK`.

`drop_handler` builds a disabling `stack_t`, calls `sigaltstack(&disabling_stack, ptr::null_mut())`, ignores the return value, and then unconditionally calls:

```rust
munmap(data.sub(page_size), sigstack_size + page_size)
```

The reproduced lifecycle was:

1. Install an alternate signal stack.
2. Enter an `SA_ONSTACK` signal handler.
3. Attempt `sigaltstack(SS_DISABLE)` from that active altstack.
4. Observe `sigaltstack` return `-1` with `errno=EINVAL`.
5. Ignore the failure and `munmap` the installed stack.
6. Process crashes immediately when the active stack mapping is unmapped.

This matches the platform behavior for attempting to disable an active alternate signal stack.

## Why This Is A Real Bug

`sigaltstack(SS_DISABLE)` is fallible. When it fails, the kernel's per-thread alternate-stack state remains installed and still names the same memory region.

The original code violates the required resource lifecycle ordering by freeing the memory even though ownership was not successfully detached from the kernel. This creates a stale kernel reference to unmapped memory and is reachable from `Handler::drop` and `cleanup`.

Impact is at least reliable process crash / denial of service.

## Fix Requirement

Only unmap the alternate-stack mapping after `sigaltstack(SS_DISABLE)` succeeds.

## Patch Rationale

The patch checks the return value from `sigaltstack`. `munmap` is executed only when `sigaltstack` returns `0`, meaning the alternate stack was successfully disabled and the kernel no longer references the mapping.

If disabling fails, the mapping is intentionally left intact rather than freeing memory that may still be active or kernel-referenced.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/pal/unix/stack_overflow.rs b/library/std/src/sys/pal/unix/stack_overflow.rs
index 3b951899dfe..23082bd8308 100644
--- a/library/std/src/sys/pal/unix/stack_overflow.rs
+++ b/library/std/src/sys/pal/unix/stack_overflow.rs
@@ -295,10 +295,11 @@ pub unsafe fn drop_handler(data: *mut libc::c_void) {
                 ss_size: sigstack_size,
             };
             // SAFETY: we warned the caller this disables the alternate signal stack!
-            unsafe { sigaltstack(&disabling_stack, ptr::null_mut()) };
-            // SAFETY: We know from `get_stackp` that the alternate stack we installed is part of
-            // a mapping that started one page earlier, so walk back a page and unmap from there.
-            unsafe { munmap(data.sub(page_size), sigstack_size + page_size) };
+            if unsafe { sigaltstack(&disabling_stack, ptr::null_mut()) } == 0 {
+                // SAFETY: We know from `get_stackp` that the alternate stack we installed is part of
+                // a mapping that started one page earlier, so walk back a page and unmap from there.
+                unsafe { munmap(data.sub(page_size), sigstack_size + page_size) };
+            }
         }
 
         delete_current_info();
```