# Alternate Stack Leak On Guard Setup Failure

## Classification

Resource lifecycle bug, low severity.

## Affected Locations

`library/std/src/sys/pal/unix/stack_overflow.rs:239`

## Summary

`get_stack()` allocates an alternate signal-stack mapping with `mmap64`, then protects the first page as a guard with `mprotect`. If `mprotect` fails, the function panics immediately and skips `munmap`, leaking the successful mapping until process termination.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- `NEED_ALTSTACK` is set.
- `get_stack()` is reached from `make_handler(true)` during Unix std initialization or from `Handler::new()` for spawned threads.
- `mmap64` succeeds for `sigstack_size + page_size`.
- `mprotect(stackp, page_size, PROT_NONE)` fails.

## Proof

The reproduced path is:

- `get_stack()` computes `sigstack_size` and `page_size`.
- It calls `mmap64(..., sigstack_size + page_size, PROT_READ | PROT_WRITE, ...)`.
- If `mmap64` succeeds, it calls `mprotect(stackp, page_size, PROT_NONE)`.
- Before the patch, a nonzero `mprotect` result immediately executed:
  ```rust
  panic!("failed to set up alternative stack guard page: {}", io::Error::last_os_error());
  ```
- No `munmap(stackp, sigstack_size + page_size)` occurred on that failure path.
- Normal cleanup in `drop_handler()` requires a completed `Handler` containing `stack.ss_sp`, but no `Handler` is constructed when `get_stack()` panics.

## Why This Is A Real Bug

The mapping ownership is acquired when `mmap64` succeeds. The guard setup failure path exits by panic before transferring ownership to a `Handler` or releasing the mapping. Therefore the allocation has no remaining cleanup path. The leak is bounded to a fatal setup-error path, but it is still a real resource lifecycle defect.

## Fix Requirement

On `mprotect` failure after successful `mmap64`, release the full mapping with:

```rust
munmap(stackp, sigstack_size + page_size);
```

before panicking.

## Patch Rationale

The patch stores `io::Error::last_os_error()` before cleanup so the panic reports the original `mprotect` failure. It then calls `munmap` on the original mapping base and full mapping length before panicking. This mirrors the later `drop_handler()` cleanup logic, which unmaps from one page before the alternate-stack pointer over the same `sigstack_size + page_size` range.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/pal/unix/stack_overflow.rs b/library/std/src/sys/pal/unix/stack_overflow.rs
index 3b951899dfe..5d92b136144 100644
--- a/library/std/src/sys/pal/unix/stack_overflow.rs
+++ b/library/std/src/sys/pal/unix/stack_overflow.rs
@@ -237,7 +237,9 @@ unsafe fn get_stack() -> libc::stack_t {
         }
         let guard_result = libc::mprotect(stackp, page_size, PROT_NONE);
         if guard_result != 0 {
-            panic!("failed to set up alternative stack guard page: {}", io::Error::last_os_error());
+            let error = io::Error::last_os_error();
+            munmap(stackp, sigstack_size + page_size);
+            panic!("failed to set up alternative stack guard page: {error}");
         }
         let stackp = stackp.add(page_size);
```