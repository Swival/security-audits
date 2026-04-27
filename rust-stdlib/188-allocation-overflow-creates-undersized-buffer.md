# allocation overflow creates undersized buffer

## Classification

High severity vulnerability: integer overflow leading to undersized allocation and out-of-bounds read.

Confidence: certain.

## Affected Locations

`library/std/src/sys/env/zkvm.rs:16`

## Summary

`getenv` trusts the byte count returned by `abi::sys_getenv` after only rejecting the `usize::MAX` sentinel. On the 32-bit zkvm target, large non-sentinel values can overflow the rounding expression used to compute the word allocation size. This can allocate too few words, then build and copy a byte slice using the original large `nbytes`, violating slice validity and reading far beyond the allocation.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched.

## Preconditions

`abi::sys_getenv` returns a value greater than `usize::MAX - WORD_SIZE + 1` and not equal to the `usize::MAX` sentinel.

For the reproduced 32-bit zkvm case, practical vulnerable values include:

- `usize::MAX - 2`
- `usize::MAX - 1`

## Proof

The first `abi::sys_getenv` call returns the required byte count into `nbytes`.

The code rejects only:

```rust
if nbytes == usize::MAX {
    return None;
}
```

It then computes:

```rust
let nwords = (nbytes + WORD_SIZE - 1) / WORD_SIZE;
```

On a 32-bit zkvm target with `WORD_SIZE == 4`, `nbytes == 0xfffffffd` causes release arithmetic wrap:

```text
0xfffffffd + 3 == 0
nwords == 0
```

The code then calls:

```rust
abi::sys_alloc_words(0)
```

but later constructs a byte slice using the original large `nbytes`:

```rust
crate::slice::from_raw_parts(words.cast() as *const u8, nbytes)
```

and copies it with:

```rust
u8s.to_vec()
```

This creates an invalid slice and can read far beyond the allocated region.

## Why This Is A Real Bug

The overflow occurs before allocation size calculation completes. The resulting `nwords` can be smaller than required, including zero, while the later read length remains the attacker-controlled or host-controlled `nbytes`.

The public `getenv` path exposes this behavior through environment variable lookup. The second `sys_getenv` call and subsequent `from_raw_parts` do not revalidate that the allocated buffer is large enough for `nbytes`.

Although `nbytes == usize::MAX` is handled as a sentinel and returns `None`, adjacent large values are not rejected and reproduce the issue.

## Fix Requirement

The allocation rounding must be checked before allocation. If adding `WORD_SIZE - 1` would overflow, `getenv` must fail safely instead of wrapping and allocating an undersized buffer.

## Patch Rationale

The patch replaces unchecked addition with checked addition:

```rust
let nwords = nbytes.checked_add(WORD_SIZE - 1)? / WORD_SIZE;
```

Because `getenv` returns `Option<OsString>`, the `?` operator converts overflow into `None`. This preserves existing failure semantics and prevents the wrapped allocation size from being used.

For valid sizes, the calculation remains equivalent to the prior round-up division.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/env/zkvm.rs b/library/std/src/sys/env/zkvm.rs
index b672a03bf0b..e5c2898ee49 100644
--- a/library/std/src/sys/env/zkvm.rs
+++ b/library/std/src/sys/env/zkvm.rs
@@ -15,7 +15,7 @@ pub fn getenv(varname: &OsStr) -> Option<OsString> {
         return None;
     }
 
-    let nwords = (nbytes + WORD_SIZE - 1) / WORD_SIZE;
+    let nwords = nbytes.checked_add(WORD_SIZE - 1)? / WORD_SIZE;
     let words = unsafe { abi::sys_alloc_words(nwords) };
 
     let nbytes2 = unsafe { abi::sys_getenv(words, nwords, varname.as_ptr(), varname.len()) };
```