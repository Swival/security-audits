# Saved Surrogate Triggers Out-Of-Bounds Slice

## Classification

Invariant violation, medium severity.

## Affected Locations

- `library/std/src/sys/stdio/windows.rs:336`
- `library/std/src/sys/stdio/windows.rs:337`

## Summary

`Stdin::read` can allocate a one-`u16` temporary buffer and pass it to `read_u16s_fixup_surrogates` with `amount == 1`. If a saved high surrogate is present, the helper inserts it at `buf[0]`, changes `amount` from `1` to `2`, then slices `buf[1..2]`. With a one-element buffer, this panics before calling `ReadConsoleW`.

## Provenance

Confirmed from the provided source, reproduced control-flow evidence, and patch.

Originally reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Windows console stdin path is used.
- `self.surrogate != 0`, meaning a prior read ended with a high surrogate.
- Caller supplies a byte buffer with fewer than four bytes of remaining output capacity.
- `Stdin::read` enters the small-output-buffer branch and creates a one-element `utf16_buf`.

## Proof

In `Stdin::read`, when `buf.len() - bytes_copied < 4`, the original code allocates:

```rust
let mut utf16_buf = [MaybeUninit::new(0); 1];
let read = read_u16s_fixup_surrogates(handle, &mut utf16_buf, 1, &mut self.surrogate)?;
```

Inside `read_u16s_fixup_surrogates`, a saved surrogate follows this path:

```rust
if *surrogate != 0 {
    buf[0] = MaybeUninit::new(*surrogate);
    *surrogate = 0;
    start = 1;
    if amount == 1 {
        amount = 2;
    }
}
let mut amount = read_u16s(handle, &mut buf[start..amount])? + start;
```

For a one-element `buf`, this forms `buf[1..2]`, exceeding `buf.len() == 1`. The reproduced minimal Rust control flow panicked with:

```text
range end index 2 out of range for slice of length 1
```

The saved-surrogate state is reachable because the same helper stores a high surrogate for the next read when a read ends with one:

```rust
if matches!(last_char, 0xD800..=0xDBFF) {
    *surrogate = last_char;
    amount -= 1;
}
```

## Why This Is A Real Bug

The helper assumes that when `amount == 1` and a saved surrogate exists, the backing buffer can hold two `u16` values. The small-buffer branch in `Stdin::read` violated that invariant by passing a one-element array. This creates a deterministic bounds-check panic from safe Rust slicing before any operating-system read occurs.

## Fix Requirement

Ensure `read_u16s_fixup_surrogates` is never asked to expand `amount` beyond the actual `buf.len()`, or avoid increasing `amount` past the provided buffer length.

## Patch Rationale

The patch changes the small-output-buffer temporary UTF-16 buffer from one element to two elements:

```diff
-            let mut utf16_buf = [MaybeUninit::new(0); 1];
+            let mut utf16_buf = [MaybeUninit::new(0); 2];
```

This satisfies the helper’s documented local assumption: with a saved surrogate and `amount == 1`, there is now room for the saved surrogate at `buf[0]` and one newly read `u16` at `buf[1]`. The call still requests `amount == 1`, preserving the intended read behavior while making the expanded `buf[1..2]` slice valid.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/stdio/windows.rs b/library/std/src/sys/stdio/windows.rs
index 62ec115d7b0..3106d6c62c2 100644
--- a/library/std/src/sys/stdio/windows.rs
+++ b/library/std/src/sys/stdio/windows.rs
@@ -278,7 +278,7 @@ fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
             Ok(bytes_copied)
         } else if buf.len() - bytes_copied < 4 {
             // Not enough space to get a UTF-8 byte. We will use the incomplete UTF8.
-            let mut utf16_buf = [MaybeUninit::new(0); 1];
+            let mut utf16_buf = [MaybeUninit::new(0); 2];
             // Read one u16 character.
             let read = read_u16s_fixup_surrogates(handle, &mut utf16_buf, 1, &mut self.surrogate)?;
             // Read bytes, using the (now-empty) self.incomplete_utf8 as extra space.
```