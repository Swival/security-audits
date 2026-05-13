# UTF8 cache output skips integrity check

## Classification

security_control_failure, high severity, confidence certain

## Affected Locations

`src/jsc/RuntimeTranspilerCache.rs:446`

## Summary

`Entry::load` validated cached transpiler output integrity for LATIN1 and UTF16 encodings, but not for UTF8. A cache file with valid outer metadata and `output_encoding = UTF8` could supply tampered JavaScript bytes and still be accepted as a cache hit.

## Provenance

Verified by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- Victim loads a runtime transpiler cache file.
- The cache file metadata has matching `input_hash`, `input_byte_length`, and `features_hash`.
- The metadata selects `output_encoding = UTF8`.
- The output bytes are attacker-controlled or otherwise tampered.

## Proof

`RuntimeTranspilerCache::from_file_with_cache_file_path` decodes cache metadata and verifies only the input hash, input size, and feature hash before calling `Entry::load`.

In `Entry::load`, the LATIN1 and UTF16 branches compare the loaded output bytes against `metadata.output_hash` when it is nonzero and return `InvalidHash` on mismatch. The UTF8 branch only reads bytes with `pread_box` and immediately returns `OutputCode::Utf8(utf8)`.

Because `Entry::save` writes `metadata.output_hash = hash(output_bytes)`, the intended invariant is that loaded output bytes match `metadata.output_hash`. The UTF8 load path did not enforce that invariant.

Impact path:

```text
attacker-controlled cache file
-> valid decoded metadata
-> input/features checks pass
-> UTF8 branch reads tampered bytes
-> no output hash validation
-> from_file_with_cache_file_path returns Ok(entry)
-> tampered JavaScript is accepted as cached transpiler output
```

## Why This Is A Real Bug

The code already treats `metadata.output_hash` as the integrity control for cached output. LATIN1 and UTF16 enforce it, and save-time metadata generation populates it for all encodings. UTF8 was the only output encoding that failed open, so the cache integrity policy was inconsistently applied to the most common byte output path.

## Fix Requirement

Compare `hash(utf8)` against `metadata.output_hash` in the UTF8 load branch when `metadata.output_hash != 0`, and return `InvalidHash` on mismatch.

## Patch Rationale

The patch mirrors the existing LATIN1 and UTF16 validation logic in the UTF8 branch. It preserves the existing compatibility behavior that skips validation when `metadata.output_hash == 0`, while enforcing integrity for normal saved cache entries where the hash is populated.

## Residual Risk

None

## Patch

```diff
diff --git a/src/jsc/RuntimeTranspilerCache.rs b/src/jsc/RuntimeTranspilerCache.rs
index 9fdd40f8b8..72fac1b6e0 100644
--- a/src/jsc/RuntimeTranspilerCache.rs
+++ b/src/jsc/RuntimeTranspilerCache.rs
@@ -446,6 +446,11 @@ impl Entry {
                         self.metadata.output_byte_length as usize,
                         self.metadata.output_byte_offset,
                     )?;
+                    if self.metadata.output_hash != 0 {
+                        if hash(&utf8) != self.metadata.output_hash {
+                            return Err(bun_core::err!(InvalidHash));
+                        }
+                    }
                     OutputCode::Utf8(utf8)
                 }
                 Encoding::LATIN1 => {
```