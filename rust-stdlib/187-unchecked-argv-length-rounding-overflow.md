# unchecked argv length rounding overflow

## Classification

Vulnerability, medium severity, confidence certain.

## Affected Locations

`library/std/src/sys/args/zkvm.rs:19`

## Summary

The zkvm argv collection code rounded byte lengths to word lengths with unchecked arithmetic:

```rust
(arg_len + WORD_SIZE - 1) / WORD_SIZE
```

If the zkvm ABI reports an argument length greater than `usize::MAX - WORD_SIZE + 1`, the addition overflows before allocation. In debug builds this panics on integer overflow. In release builds it wraps, causing an undersized allocation that is later paired with the original oversized `arg_len` when constructing a slice.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- The zkvm ABI returns `arg_len > usize::MAX - WORD_SIZE + 1`.
- `std::env::args` initializes `ARGS` on zkvm.
- A malformed or hostile zkvm argv provider can influence the value returned by `abi::sys_argv(ptr::null_mut(), 0, i)`.

## Proof

`arg_len` originates from:

```rust
abi::sys_argv(ptr::null_mut(), 0, i)
```

The affected code then computed:

```rust
let arg_len_words = (arg_len + WORD_SIZE - 1) / WORD_SIZE;
```

For `WORD_SIZE == 4`, any `arg_len > usize::MAX - 3` overflows during `arg_len + WORD_SIZE - 1`.

Observed behavior:

- In debug builds, checked integer overflow causes a panic.
- In release builds, the addition wraps.
- For `arg_len` values `usize::MAX - 2` through `usize::MAX`, `arg_len_words` becomes `0`.
- The wrapped value is used for allocation at `library/std/src/sys/args/zkvm.rs:20`.
- The original huge `arg_len` is later used at `library/std/src/sys/args/zkvm.rs:25`:

```rust
let arg_bytes = unsafe { slice::from_raw_parts(words.cast(), arg_len) };
```

This creates a slice whose length is not backed by the allocation returned for the wrapped word count.

## Why This Is A Real Bug

The code relies on an ABI-supplied length before validating that the rounding arithmetic is representable. In release builds, wrapping can cause the allocation size to be much smaller than the slice length subsequently created from the same pointer.

That violates `slice::from_raw_parts` validity requirements because the memory region described by `arg_len` bytes is not actually allocated. Consequences include undefined behavior, crash, or memory exposure when the argument is used.

## Fix Requirement

Use checked arithmetic before rounding the ABI-provided byte length to words, and abort before allocation or slice construction if the rounded length cannot be represented.

## Patch Rationale

The patch replaces unchecked addition with `checked_add`:

```rust
let arg_len_words = arg_len.checked_add(WORD_SIZE - 1).expect("argument length overflow") / WORD_SIZE;
```

This preserves the existing rounding formula for valid lengths while preventing wraparound for invalid ABI lengths. On overflow, execution stops before `sys_alloc_words` receives an undersized count and before `slice::from_raw_parts` can be called with an invalid huge length.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/args/zkvm.rs b/library/std/src/sys/args/zkvm.rs
index d26bf1eaff9..a1054fc2887 100644
--- a/library/std/src/sys/args/zkvm.rs
+++ b/library/std/src/sys/args/zkvm.rs
@@ -16,7 +16,7 @@ fn get_args() -> Vec<&'static OsStr> {
         // Get the size of the argument then the data.
         let arg_len = unsafe { abi::sys_argv(ptr::null_mut(), 0, i) };
 
-        let arg_len_words = (arg_len + WORD_SIZE - 1) / WORD_SIZE;
+        let arg_len_words = arg_len.checked_add(WORD_SIZE - 1).expect("argument length overflow") / WORD_SIZE;
         let words = unsafe { abi::sys_alloc_words(arg_len_words) };
 
         let arg_len2 = unsafe { abi::sys_argv(words, arg_len_words, i) };
```