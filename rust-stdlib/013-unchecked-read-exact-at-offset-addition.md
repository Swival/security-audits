# unchecked read_exact_at offset addition

## Classification

Invariant violation, medium severity. Confidence: certain.

## Affected Locations

`library/std/src/os/unix/fs.rs:124`

## Summary

`FileExt::read_exact_at` advances its caller-supplied `u64` offset with unchecked addition after each successful `read_at`. If the initial offset is near `u64::MAX` and `read_at` returns bytes, the offset can wrap in normal builds or panic in overflow-checking builds. This violates the offset progression invariant and can redirect subsequent reads to the wrong offset.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- Caller invokes the stable Unix `FileExt::read_exact_at` API.
- Caller supplies an offset near `u64::MAX`.
- The underlying `read_at` succeeds and returns at least one byte.
- The requested buffer is large enough for another loop iteration after the overflowing advancement.

## Proof

The affected implementation accepts `offset` as a caller-controlled `u64`:

```rust
fn read_exact_at(&self, mut buf: &mut [u8], mut offset: u64) -> io::Result<()>
```

On every successful partial read, it advances the remaining buffer and then performs unchecked offset addition:

```rust
Ok(n) => {
    let tmp = buf;
    buf = &mut tmp[n..];
    offset += n as u64;
}
```

The finding was reproduced:

- On Linux, `/dev/zero`, `/dev/urandom`, and `/dev/random` returned successful reads at `offset = u64::MAX` and `offset = u64::MAX - 1`.
- `File::read_exact_at(&mut [0; 2], u64::MAX)` against `/dev/zero` returned `Ok(())`, so the implementation necessarily executed `offset += 2`, overflowing `u64`.
- A minimal valid `FileExt` implementor that returns one byte per `read_at` observed calls first at `18446744073709551615` and then at `0`, proving wraparound propagation to a wrong subsequent offset.

## Why This Is A Real Bug

This is reachable through a stable standard-library API on Unix. The precondition is practical for Unix special files, not merely theoretical: successful reads at maximal offsets were observed on real Linux devices. Once the first read succeeds, the unchecked addition can wrap from `u64::MAX` to `0`, causing the next read to target the beginning of the offset space rather than reporting invalid input. In overflow-checking builds, the same operation can panic instead of returning an `io::Result` error.

## Fix Requirement

Replace unchecked offset advancement with checked addition and return an error when the next offset cannot be represented as `u64`.

## Patch Rationale

The patch changes only the offset update in `read_exact_at`:

```rust
offset = offset.checked_add(n as u64).ok_or(io::ErrorKind::InvalidInput)?;
```

This preserves existing behavior for all representable offset progressions and converts overflow into an `InvalidInput` error. It prevents silent wraparound and avoids overflow-checking panics while keeping the API contract error-based.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/os/unix/fs.rs b/library/std/src/os/unix/fs.rs
index 219b340b924..ba8de2e50ba 100644
--- a/library/std/src/os/unix/fs.rs
+++ b/library/std/src/os/unix/fs.rs
@@ -122,7 +122,7 @@ fn read_exact_at(&self, mut buf: &mut [u8], mut offset: u64) -> io::Result<()> {
                 Ok(n) => {
                     let tmp = buf;
                     buf = &mut tmp[n..];
-                    offset += n as u64;
+                    offset = offset.checked_add(n as u64).ok_or(io::ErrorKind::InvalidInput)?;
                 }
                 Err(ref e) if e.is_interrupted() => {}
                 Err(e) => return Err(e),
```