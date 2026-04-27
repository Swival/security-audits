# Unchecked Terminfo String Offset Panics

## Classification

- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations

- `library/test/src/term/terminfo/parser/compiled.rs:289`
- `library/test/src/term/terminfo/parser/compiled.rs:303`
- Reachability: `library/test/src/term/terminfo/mod.rs:104`

## Summary

Compiled terminfo parsing accepted string offsets from attacker-controlled input without validating that each offset was within the string table. A malformed terminfo file could set a present string offset greater than the string table length, causing Rust slice indexing to panic instead of returning a parser error.

## Provenance

- Finding verified and reproduced from supplied evidence.
- Scanner provenance: [Swival Security Scanner](https://swival.dev)

## Preconditions

- The caller parses a compiled terminfo file through `TermInfo::_from_path` or another path reaching `parse`.
- The compiled terminfo contains a present string capability offset greater than the string table length.
- The malformed offset is not one of the sentinel values `0xFFFF` or `0xFFFE`.

## Proof

- `TermInfo::_from_path` opens a terminfo file and calls `parse(&mut reader, false)` at `library/test/src/term/terminfo/mod.rs:104`.
- `parse` reads string offsets from the file into `string_offsets` at `library/test/src/term/terminfo/parser/compiled.rs:278`.
- Each present offset is cast to `usize` at `library/test/src/term/terminfo/parser/compiled.rs:292`.
- The offset is then used directly in `string_table[offset..string_table_bytes]` at `library/test/src/term/terminfo/parser/compiled.rs:303`.
- A minimal valid header with `string_offsets_count = 1`, `string_table_bytes = 1`, and first string offset `2` panics with `range start index 2 out of range for slice of length 1`.

## Why This Is A Real Bug

The parser already treats malformed terminfo data as recoverable input errors in surrounding validation paths. This malformed offset is also controlled by the compiled terminfo file, but instead of returning `Err`, it reaches unchecked slice indexing and aborts parsing with a panic. Malformed local terminfo data can therefore crash the caller.

## Fix Requirement

Reject any non-sentinel string offset greater than the actual string table length before slicing.

## Patch Rationale

The patch adds an explicit bounds check after handling the `0xFFFE` sentinel and before constructing the slice. This preserves existing sentinel behavior while converting out-of-bounds offsets into a structured parser error:

```rust
if offset > string_table.len() {
    return Err("invalid file: string offset out of bounds".to_string());
}
```

The check uses `string_table.len()` because it reflects the actual number of bytes read, and prevents `string_table[offset..string_table_bytes]` from panicking when `offset` is beyond the available table.

## Residual Risk

None

## Patch

```diff
diff --git a/library/test/src/term/terminfo/parser/compiled.rs b/library/test/src/term/terminfo/parser/compiled.rs
index d1dd0f10d86..071c24015ab 100644
--- a/library/test/src/term/terminfo/parser/compiled.rs
+++ b/library/test/src/term/terminfo/parser/compiled.rs
@@ -299,6 +299,10 @@ macro_rules! read_nonneg {
                     return Ok((name.to_string(), Vec::new()));
                 }
 
+                if offset > string_table.len() {
+                    return Err("invalid file: string offset out of bounds".to_string());
+                }
+
                 // Find the offset of the NUL we want to go to
                 let nulpos = string_table[offset..string_table_bytes].iter().position(|&b| b == 0);
                 match nulpos {
```