# Unchecked Mach-O Slice Bounds Abort Build

## Classification

Denial of service, low severity. Build-time only; not reachable from the running database. `build_multiversion.zig` runs during the multiversion release build and consumes `tigerbeetle_past` artifacts produced by earlier builds. A malformed artifact aborts the release pipeline, which is loud but bounded.

Note: the runtime equivalent, `parse_macho` in `src/multiversion.zig`, already validates more aggressively (commit `744e8fe1f` recently turned duplicate-CPU asserts into proper errors). Mirroring that hardening in the build helper is the consistent move.

## Affected Locations

`src/build_multiversion.zig:746`

## Summary

`macos_universal_binary_extract` trusted attacker-controlled Mach-O fat slice `offset` and `size` fields before slicing `binary_contents`. A malformed macOS universal `tigerbeetle_past` binary could set a matching architecture slice outside the file bounds, causing Zig bounds-check panic and aborting the multiversion release build.

## Provenance

Verified by Swival.dev Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The build target is macOS.
- The build consumes attacker-supplied or attacker-modified `tigerbeetle_past`.
- The crafted `tigerbeetle_past` preserves enough valid multiversion metadata for parsing to reach Mach-O slice extraction.
- The matching native `fat_arch.offset` / `fat_arch.size` points outside `binary_contents`.

## Proof

`build_multiversion_body` calls `macos_universal_binary_extract` for macOS past binaries.

Inside `macos_universal_binary_extract`, the function:

- reads `input_path` into `binary_contents`;
- parses the fat header and fat arch entries;
- finds the entry matching `CPU_TYPE_ARM64` or `CPU_TYPE_X86_64`;
- byte-swaps attacker-controlled `fat_arch.offset` and `fat_arch.size`;
- uses them directly in `binary_contents[offset..][0..size]`.

Before the patch, no check ensured that `offset <= binary_contents.len` or that `offset + size <= binary_contents.len`.

A minimal equivalent Zig reproduction with a 128-byte fat binary and matching slice `offset = 120`, `size = 16` panics with:

```text
index out of bounds: index 136, len 128
```

This aborts the macOS multiversion build before the output binary is produced.

## Why This Is A Real Bug

The `fat_arch` table is part of the supplied Mach-O universal binary and is therefore attacker-controlled under the stated preconditions. Zig slice bounds checks trap on invalid ranges. Because the function performs the slice directly, a malformed but otherwise parseable past binary can deterministically terminate the build helper.

The multiversion metadata validation does not protect this operation because the failing fields are the normal Mach-O `CPU_TYPE_ARM64` / `CPU_TYPE_X86_64` slice offsets and sizes used later by extraction.

## Fix Requirement

Validate the selected Mach-O slice before slicing:

- `offset` must be within `binary_contents`.
- `size` must not exceed the remaining bytes after `offset`.
- Invalid slices must return an error instead of triggering a bounds-check panic.

## Patch Rationale

The patch adds an explicit bounds check immediately after reading the selected `fat_arch.offset` and `fat_arch.size`:

```zig
if (offset > binary_contents.len or size > binary_contents.len - offset) {
    return error.InvalidMachO;
}
```

This prevents both out-of-bounds starts and integer-overflow-prone `offset + size` checks by comparing `size` against `binary_contents.len - offset` only after confirming `offset <= binary_contents.len`.

Invalid input now fails as `error.InvalidMachO` rather than aborting the process through a runtime panic.

## Residual Risk

None

## Patch

```diff
diff --git a/src/build_multiversion.zig b/src/build_multiversion.zig
index 4cbaee446..666cbc27c 100644
--- a/src/build_multiversion.zig
+++ b/src/build_multiversion.zig
@@ -739,6 +739,9 @@ fn macos_universal_binary_extract(
         {
             const offset = @byteSwap(fat_arch.offset);
             const size = @byteSwap(fat_arch.size);
+            if (offset > binary_contents.len or size > binary_contents.len - offset) {
+                return error.InvalidMachO;
+            }
 
             try shell.cwd.writeFile(.{
                 .sub_path = output_path,
```