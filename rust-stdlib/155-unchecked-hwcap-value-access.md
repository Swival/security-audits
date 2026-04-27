# unchecked hwcap value access

## Classification

Low severity validation gap.

Confidence: certain.

## Affected Locations

- `library/std_detect/src/detect/os/linux/auxvec.rs:203`
- `library/std_detect/src/detect/os/linux/auxvec.rs:205`

## Summary

`auxv_from_buf` iterated auxiliary-vector words with `buf.chunks(2)` and then unconditionally read `el[1]` for `AT_HWCAP` and `AT_HWCAP2` entries. If malformed auxv bytes produced a final odd one-word chunk whose key decoded to `AT_HWCAP`, the parser panicked with an out-of-bounds access instead of returning `Err`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- `auxv_from_file_bytes` receives malformed or truncated auxv bytes.
- The malformed input ends with a lone auxv key word.
- That lone key word decodes to `AT_HWCAP`, or to `AT_HWCAP2` on architectures that parse it.

## Proof

`auxv_from_file_bytes` allocates `1 + len / size_of::<usize>()` words and copies arbitrary input bytes into that buffer.

`auxv_from_buf` then iterates the resulting `usize` buffer using `buf.chunks(2)`. `chunks(2)` may yield a final one-element chunk when the buffer length is odd.

For such a final one-element chunk:

```rust
match el[0] {
    AT_NULL => break,
    AT_HWCAP => return Ok(AuxVec { hwcap: el[1] }),
    _ => (),
}
```

or, on architectures with `AT_HWCAP2`:

```rust
match el[0] {
    AT_NULL => break,
    AT_HWCAP => hwcap = Some(el[1]),
    AT_HWCAP2 => hwcap2 = el[1],
    _ => (),
}
```

`el[0]` is valid, but `el[1]` is absent. A malformed input such as a single little-endian byte `[0x10]`, which decodes to `AT_HWCAP`, reaches this state and panics with:

```text
index out of bounds: the len is 1 but the index is 1
```

## Why This Is A Real Bug

The function contract says malformed or unreadable auxiliary-vector data should result in an error path, not a panic. `auxv_from_file` can reach this parser through file bytes, so truncated or malformed auxv content can trigger process panic during runtime feature detection fallback.

The exposure is limited because normal `/proc/self/auxv` is expected to be well-formed, and many Linux targets use `getauxval` first. However, the fallback parser still accepts byte input and should handle malformed data safely.

## Fix Requirement

The parser must only process complete `(key, value)` auxv pairs. A trailing lone key word must be ignored or treated as malformed without indexing past the chunk boundary.

## Patch Rationale

The patch replaces `buf.chunks(2)` with `buf.chunks_exact(2)` in both auxv parsing loops.

`chunks_exact(2)` yields only complete two-word entries, so every yielded `el` has both `el[0]` and `el[1]`. Any trailing one-word remainder is excluded from iteration, preventing the out-of-bounds access while preserving behavior for valid auxv pairs.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std_detect/src/detect/os/linux/auxvec.rs b/library/std_detect/src/detect/os/linux/auxvec.rs
index c0bbc7d4efa..802ec35414f 100644
--- a/library/std_detect/src/detect/os/linux/auxvec.rs
+++ b/library/std_detect/src/detect/os/linux/auxvec.rs
@@ -179,7 +179,7 @@ fn auxv_from_buf(buf: &[usize]) -> Result<AuxVec, alloc::string::String> {
         target_arch = "loongarch64",
     ))]
     {
-        for el in buf.chunks(2) {
+        for el in buf.chunks_exact(2) {
             match el[0] {
                 AT_NULL => break,
                 AT_HWCAP => return Ok(AuxVec { hwcap: el[1] }),
@@ -199,7 +199,7 @@ fn auxv_from_buf(buf: &[usize]) -> Result<AuxVec, alloc::string::String> {
         let mut hwcap = None;
         // For some platforms, AT_HWCAP2 was added recently, so let it default to zero.
         let mut hwcap2 = 0;
-        for el in buf.chunks(2) {
+        for el in buf.chunks_exact(2) {
             match el[0] {
                 AT_NULL => break,
                 AT_HWCAP => hwcap = Some(el[1]),
```