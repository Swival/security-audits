# Truncated String Table Panics

## Classification

Validation gap, medium severity.

## Affected Locations

`library/test/src/term/terminfo/parser/compiled.rs:303`

## Summary

The compiled terminfo parser trusted the header-declared `string_table_bytes` length after reading the string table with `Read::take(...).read_to_end(...)`. At EOF, `read_to_end` can succeed with fewer bytes than requested. The parser later sliced `string_table[offset..string_table_bytes]`, using the advertised length instead of the actual vector length, allowing a truncated input to panic instead of returning an error.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

A compiled terminfo file must:

- Advertise `string_table_bytes` larger than the bytes actually readable.
- Include at least one string offset.
- Use a present string offset, such as `0`, so the string table lookup path executes.

## Proof

A minimal reproducer was confirmed with:

- Valid magic `0432`.
- `names_bytes = 1`.
- `string_offsets_count = 1`.
- `string_table_bytes = 10`.
- One present string offset `0`.
- Zero actual string table bytes.

Runtime result:

```text
panicked at library/test/src/term/terminfo/parser/compiled.rs:303:42:
range end index 10 out of range for slice of length 0
```

The vulnerable path is reachable through `TermInfo::from_path`, which opens a terminfo file and calls `parse` at `library/test/src/term/terminfo/mod.rs:103`.

## Why This Is A Real Bug

`string_table_bytes` is file-controlled header data. The parser reads at most that many bytes, but does not verify that the read produced that exact length. When the input reaches EOF early, `string_table.len()` is smaller than `string_table_bytes`. The subsequent slice `string_table[offset..string_table_bytes]` can therefore exceed the real allocation bounds and panic.

This violates parser error-handling expectations: malformed input should produce `Err(...)`, not an uncontrolled panic.

## Fix Requirement

After reading the string table, validate that the number of bytes read exactly matches the header-declared `string_table_bytes` before any slicing occurs.

## Patch Rationale

The patch adds an explicit length check immediately after `read_to_end`:

```rust
if string_table.len() != string_table_bytes {
    return Err("invalid file: truncated string table".to_string());
}
```

This preserves the existing parser model, which treats incompatible or malformed terminfo data as `Err(String)`, and prevents later slices from using an advertised bound that exceeds the actual buffer length.

## Residual Risk

None

## Patch

```diff
diff --git a/library/test/src/term/terminfo/parser/compiled.rs b/library/test/src/term/terminfo/parser/compiled.rs
index d1dd0f10d86..e471f158daf 100644
--- a/library/test/src/term/terminfo/parser/compiled.rs
+++ b/library/test/src/term/terminfo/parser/compiled.rs
@@ -280,6 +280,9 @@ macro_rules! read_nonneg {
 
         let mut string_table = Vec::new();
         t!(file.take(string_table_bytes as u64).read_to_end(&mut string_table));
+        if string_table.len() != string_table_bytes {
+            return Err("invalid file: truncated string table".to_string());
+        }
 
         t!(string_offsets
             .into_iter()
```