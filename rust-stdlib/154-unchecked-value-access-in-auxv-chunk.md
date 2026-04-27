# Unchecked Value Access in auxv Chunk

## Classification

Validation gap, low severity. Confidence: certain.

## Affected Locations

`library/std_detect/src/detect/os/linux/auxvec.rs:183`

## Summary

`auxv_from_buf` parsed auxiliary-vector data with `buf.chunks(2)` and then unconditionally accessed `el[1]`. If the final chunk contained only one `usize` and `el[0] == AT_HWCAP`, parsing panicked with an out-of-bounds index instead of returning `Err`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- `auxv_from_file_bytes` receives bytes that decode into an odd count of `usize` values.
- The final one-element chunk has `AT_HWCAP` as its key.
- Parsing reaches the `/proc/self/auxv` fallback path or a caller/test invokes `auxv_from_file_bytes` directly.

## Proof

`auxv_from_file_bytes` allocates a `usize` buffer sized as `1 + len / size_of::<usize>()`, copies all caller-provided bytes into it, and passes the full buffer to `auxv_from_buf`.

`auxv_from_buf` then iterates with `buf.chunks(2)`. `chunks(2)` may yield a final one-element slice. If that final slice is `[AT_HWCAP]`, the match arm for `AT_HWCAP` reads `el[1]`, which is out of bounds.

A PoC using the same allocation/copy/chunks logic with `[1usize, 2usize]` plus trailing byte `0x10` reproduced the panic:

```text
index out of bounds: the len is 1 but the index is 1
```

## Why This Is A Real Bug

The parser accepts byte input from `auxv_from_file_bytes` and expects malformed auxiliary-vector data to fail gracefully. Instead, a truncated or malformed auxv buffer can cause a panic during feature detection fallback parsing.

The impact is limited because normal kernel-provided `/proc/self/auxv` data should contain complete key/value pairs, but the parser itself did not enforce that invariant before indexing.

## Fix Requirement

Iterate only over complete `(key, value)` pairs or explicitly check chunk length before accessing `el[1]`.

## Patch Rationale

Replacing `chunks(2)` with `chunks_exact(2)` makes the parser ignore an incomplete trailing word. Every loop iteration is then guaranteed to contain both `el[0]` and `el[1]`, preserving existing behavior for valid auxv pairs while preventing out-of-bounds access on malformed trailing data.

The same fix is applied to both target-specific parsing blocks:
- targets using only `AT_HWCAP`
- targets using both `AT_HWCAP` and `AT_HWCAP2`

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