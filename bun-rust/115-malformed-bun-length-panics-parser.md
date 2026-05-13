# Malformed `.bun` Length Panics Parser

## Classification

Denial of service, medium severity, certain confidence.

## Affected Locations

`src/exe_format/pe.rs:751`

## Summary

`PEFile::get_bun_section_data` parses an attacker-controlled 8-byte `.bun` section length prefix and adds it to the u64 header size using unchecked arithmetic. A crafted PE file can set this prefix near `u64::MAX`, causing an overflow panic in debug or overflow-checking builds. In normal release builds, the wrapped check can pass and a later slice operation panics. The workspace uses `panic = "abort"`, so either path aborts the consuming process instead of returning `Error::InvalidBunSection`.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

A consumer calls `PEFile::init` and then `get_bun_section_data` on attacker-supplied PE data.

## Proof

A lower-privileged local attacker supplies a PE executable containing a syntactically valid `.bun` section header and raw section range.

The `.bun` section starts with a malicious little-endian u64 length prefix such as `u64::MAX`.

`get_bun_section_data`:

- finds the exact `.bun` section name;
- verifies the raw section range is within the PE data;
- parses `section_data[0..8]` as `data_size`;
- evaluates `data_size + size_of::<u64>() as u64 > section.size_of_raw_data as u64`.

With `data_size = u64::MAX`, the unchecked addition overflows.

Observed behavior:

- debug / overflow-checking builds panic at the length check;
- normal release builds wrap the addition, allow the check to pass, and then panic at `&section_data[8..][..data_size as usize]`;
- because `Cargo.toml` sets `panic = "abort"` for dev and release profiles, the consuming process aborts.

## Why This Is A Real Bug

The function is intended to reject malformed `.bun` sections with `Error::InvalidBunSection`, but malformed attacker-controlled input can instead trigger a panic. The raw section bounds check does not constrain the embedded length prefix before arithmetic is performed. Since the process aborts under the configured panic strategy, this is a practical denial of service under the stated precondition.

## Fix Requirement

Use checked arithmetic when adding the embedded data length and the 8-byte length header. If the addition overflows, reject the section with `Error::InvalidBunSection`.

## Patch Rationale

The patch replaces unchecked `data_size + size_of::<u64>() as u64` with `checked_add`. Overflow now maps to `Error::InvalidBunSection`, preserving the parser’s error-return contract and preventing both the arithmetic overflow panic and the later out-of-bounds slice panic.

## Residual Risk

None

## Patch

```diff
diff --git a/src/exe_format/pe.rs b/src/exe_format/pe.rs
index 38f32f6016..3a2f347365 100644
--- a/src/exe_format/pe.rs
+++ b/src/exe_format/pe.rs
@@ -748,7 +748,10 @@ impl PEFile {
                         .expect("infallible: size matches"),
                 );
 
-                if data_size + size_of::<u64>() as u64 > section.size_of_raw_data as u64 {
+                let total_size = data_size
+                    .checked_add(size_of::<u64>() as u64)
+                    .ok_or(Error::InvalidBunSection)?;
+                if total_size > section.size_of_raw_data as u64 {
                     return Err(Error::InvalidBunSection);
                 }
```