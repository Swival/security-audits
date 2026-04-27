# Pending stdin bytes overwritten

## Classification

Data integrity bug. Severity: medium. Confidence: certain.

## Affected Locations

`library/std/src/sys/stdio/windows.rs:306`

## Summary

Windows console `Stdin::read` can corrupt returned stdin bytes when a prior read left pending incomplete UTF-8 bytes. The pending bytes are first copied into the caller buffer, but the subsequent large-buffer conversion writes new UTF-8 output starting at `buf[0]`, overwriting those copied bytes.

## Provenance

Verified and reproduced from the supplied finding and source evidence.

Scanner provenance: https://swival.dev

## Preconditions

- Windows console stdin path is used.
- `self.incomplete_utf8` contains pending bytes from a prior read.
- The caller-provided buffer has at least four bytes remaining after pending bytes are copied.

## Proof

A prior small read can create pending bytes through normal `Stdin::read` behavior. For example, a 1-byte read of a UTF-16 console character such as `é` converts to two UTF-8 bytes, returns the first byte, and stores the second byte in `self.incomplete_utf8`.

On the next larger read:

- `self.incomplete_utf8.read(buf)` copies the pending byte into `buf[0]`.
- `bytes_copied` is set to `1`.
- The large-buffer branch is selected because `buf.len() - bytes_copied >= 4`.
- `utf16_to_utf8(utf16s, buf)` writes newly converted UTF-8 bytes starting at `buf[0]`.
- The pending byte already copied into `buf[0]` is overwritten.
- The function still returns `bytes_copied + value`, so the caller observes corrupted bytes and may see stale preexisting buffer contents inside the reported read range.

## Why This Is A Real Bug

The corruption is reachable through ordinary console stdin reads and does not require invalid input or unsafe caller behavior. `bytes_copied` is explicitly tracked to account for bytes already placed in the caller buffer, but the later conversion ignores that offset. This violates `Read::read` expectations by reporting bytes that were not correctly written as the corresponding stdin byte stream.

## Fix Requirement

The large-buffer branch must preserve bytes already copied from `self.incomplete_utf8` by writing newly converted UTF-8 output only after `bytes_copied`.

Required change:

```rust
utf16_to_utf8(utf16s, &mut buf[bytes_copied..])
```

## Patch Rationale

The patch changes the destination slice passed to `utf16_to_utf8` from the full caller buffer to the unfilled suffix:

```diff
-            match utf16_to_utf8(utf16s, buf) {
+            match utf16_to_utf8(utf16s, &mut buf[bytes_copied..]) {
```

This keeps pending bytes already copied into `buf[..bytes_copied]` intact while preserving the existing return value calculation of `bytes_copied + value`.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/stdio/windows.rs b/library/std/src/sys/stdio/windows.rs
index 62ec115d7b0..a7e55da0e3b 100644
--- a/library/std/src/sys/stdio/windows.rs
+++ b/library/std/src/sys/stdio/windows.rs
@@ -304,7 +304,7 @@ fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
             // Safety `read_u16s_fixup_surrogates` returns the number of items
             // initialized.
             let utf16s = unsafe { utf16_buf[..read].assume_init_ref() };
-            match utf16_to_utf8(utf16s, buf) {
+            match utf16_to_utf8(utf16s, &mut buf[bytes_copied..]) {
                 Ok(value) => return Ok(bytes_copied + value),
                 Err(e) => return Err(e),
             }
```