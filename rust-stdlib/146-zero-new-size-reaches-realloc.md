# zero new size reaches realloc

## Classification

Invariant violation. Severity: medium. Confidence: certain.

## Affected Locations

`library/std/src/sys/pal/wasi/cabi_realloc.rs:51`

## Summary

`cabi_realloc` accepts external ABI inputs and allows `old_len != 0` with `new_len == 0` to reach `alloc::realloc` in release builds. The only original check was `debug_assert_ne!`, which is compiled out in release, causing a zero-size reallocation request that violates the allocator invariant requiring nonzero `new_size`.

## Provenance

Identified by Swival Security Scanner: https://swival.dev

## Preconditions

- Caller invokes exported `cabi_realloc`.
- `old_len` is nonzero.
- `new_len` is zero.
- `old_ptr` is a valid non-null allocation pointer for `old_len`.
- `align` is valid for the corresponding allocation layout.
- Build uses release semantics where `debug_assert_ne!` is removed.

## Proof

`cabi_realloc` takes ABI-controlled parameters at `library/std/src/sys/pal/wasi/cabi_realloc.rs:36`, including `old_ptr`, `old_len`, `align`, and `new_len`.

When `old_len != 0`, execution enters the reallocation branch at `library/std/src/sys/pal/wasi/cabi_realloc.rs:49`. In the vulnerable version, the only enforcement of `new_len != 0` is:

```rust
debug_assert_ne!(new_len, 0, "non-zero old_len requires non-zero new_len!");
```

Because `debug_assert_ne!` is removed in release builds, `new_len == 0` continues to:

```rust
alloc::realloc(old_ptr, layout, new_len)
```

This forwards a zero `new_len` to `alloc::realloc`. The reproduced path confirms `alloc::realloc` forwards the zero size at `library/alloc/src/alloc.rs:147`, while `GlobalAlloc::realloc` requires `new_size > 0` at `library/core/src/alloc/global.rs:247`.

## Why This Is A Real Bug

The function is externally callable through the component ABI convention and its parameters are not internally trusted. The code states the required invariant directly: nonzero `old_len` requires nonzero `new_len`. However, the vulnerable implementation enforces that invariant only in debug builds.

A release caller can therefore trigger allocator behavior with an invalid zero new size, violating the documented `GlobalAlloc::realloc` contract. This is not only a defensive assertion failure; it is reachable release behavior from ABI inputs.

## Fix Requirement

Replace the debug-only assertion with a runtime check before calling `alloc::realloc`. If `old_len != 0` and `new_len == 0`, the function must not invoke `alloc::realloc`.

## Patch Rationale

The patch changes the debug-only assertion into an unconditional runtime guard:

```rust
if new_len == 0 {
    super::abort_internal();
}
```

This preserves the stated invariant in all build modes. For invalid external ABI input, the function aborts before constructing the old layout and before forwarding zero to `alloc::realloc`.

This is consistent with nearby release-mode allocation failure handling, which also uses `super::abort_internal()` rather than pulling in formatting or panic machinery.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/pal/wasi/cabi_realloc.rs b/library/std/src/sys/pal/wasi/cabi_realloc.rs
index 78adf9002fd..dc90ad76889 100644
--- a/library/std/src/sys/pal/wasi/cabi_realloc.rs
+++ b/library/std/src/sys/pal/wasi/cabi_realloc.rs
@@ -47,7 +47,9 @@
         layout = Layout::from_size_align_unchecked(new_len, align);
         alloc::alloc(layout)
     } else {
-        debug_assert_ne!(new_len, 0, "non-zero old_len requires non-zero new_len!");
+        if new_len == 0 {
+            super::abort_internal();
+        }
         layout = Layout::from_size_align_unchecked(old_len, align);
         alloc::realloc(old_ptr, layout, new_len)
     };
```