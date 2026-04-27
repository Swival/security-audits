# Oversized Panic GFX Lend Valid Length

## Classification

Validation gap. Severity: medium. Confidence: certain.

## Affected Locations

`library/std/src/sys/stdio/xous.rs:99`

## Summary

`PanicWriter::write` copies panic text into a fixed 4096-byte graphics IPC buffer, but passed the original input slice length as the lend valid length. For writes larger than 4096 bytes, the sender advertised more valid bytes than the request buffer actually initialized for the graphics panic message.

## Provenance

Verified from the supplied reproducer and source. Originally identified by Swival Security Scanner: https://swival.dev

## Preconditions

A panic message write receives a byte slice longer than 4096 bytes, and `panic_output` successfully obtains a graphics panic connection.

## Proof

`PanicWriter::write` receives `s: &[u8]` without a length cap.

In the graphics path, the code allocates:

```rust
struct Request([u8; 4096]);
let mut request = Request([0u8; 4096]);
```

It then copies with:

```rust
for (&s, d) in s.iter().zip(request.0.iter_mut()) {
    *d = s;
}
```

The `zip` operation copies at most `request.0.len() == 4096` bytes.

Before the patch, the lend call used:

```rust
try_lend(gfx, 0 /* AppendPanicText */, &request.0, 0, s.len()).ok();
```

Thus, for `s.len() > 4096`, the request buffer contained only the first 4096 bytes, while the valid-length field claimed `s.len()` bytes.

The reproducer confirmed that `std::io::Write::write_fmt` / `write_all` can pass the oversized formatted slice to `PanicWriter::write`, and `PanicWriter::write` returns `Ok(s.len())`, so the caller does not retry or chunk the remaining text.

## Why This Is A Real Bug

The sender violates its own IPC message invariant: the graphics panic request buffer is 4096 bytes, but the valid length can exceed 4096.

`try_lend` passes the real memory range length separately from the caller-controlled valid argument. The result is a malformed graphics panic IPC message for oversized panic writes. At minimum, graphics panic output is truncated or corrupted. Any receiver that trusts the advertised valid length may process beyond the initialized panic text region.

## Fix Requirement

The graphics panic lend valid length must never exceed the number of bytes actually available in `request.0`.

Acceptable fixes are:

- chunk oversized graphics panic writes into multiple 4096-byte lends; or
- cap the valid length to `min(s.len(), request.0.len())`.

## Patch Rationale

The patch applies the minimal validation fix at the send site:

```rust
try_lend(gfx, 0 /* AppendPanicText */, &request.0, 0, s.len().min(request.0.len())).ok();
```

This preserves existing behavior and return semantics while ensuring the valid length cannot exceed the fixed 4096-byte request buffer. Oversized graphics panic text may still be truncated, but the IPC message is no longer internally inconsistent.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/stdio/xous.rs b/library/std/src/sys/stdio/xous.rs
index a92167642b7..b713930590f 100644
--- a/library/std/src/sys/stdio/xous.rs
+++ b/library/std/src/sys/stdio/xous.rs
@@ -96,7 +96,7 @@ fn write(&mut self, s: &[u8]) -> core::result::Result<usize, io::Error> {
             for (&s, d) in s.iter().zip(request.0.iter_mut()) {
                 *d = s;
             }
-            try_lend(gfx, 0 /* AppendPanicText */, &request.0, 0, s.len()).ok();
+            try_lend(gfx, 0 /* AppendPanicText */, &request.0, 0, s.len().min(request.0.len())).ok();
         }
         Ok(s.len())
     }
```