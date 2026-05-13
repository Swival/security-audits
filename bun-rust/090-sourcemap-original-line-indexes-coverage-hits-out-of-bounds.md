# sourcemap original line indexes coverage hits out of bounds

## Classification

Denial of service, medium severity.

Confidence: certain.

## Affected Locations

`src/sourcemap_jsc/CodeCoverage.rs:707`

`src/sourcemap_jsc/CodeCoverage.rs:786`

## Summary

Coverage generation with sourcemaps enabled trusts original line indexes returned from sourcemap mappings. A crafted sourcemap can return an original line index greater than or equal to the allocated coverage line count, causing out-of-bounds indexing into `line_hits_slice` or invalid bitset updates. This panics coverage generation and denies test coverage reporting.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- Coverage runs with sourcemaps enabled.
- Project files or sourcemaps are attacker-controlled.
- An executed JSC coverage block resolves through the sourcemap to an original line index outside the declared input line count.

## Proof

The sourcemap branch sizes coverage state from the parsed sourcemap header:

```rust
line_count = (parsed_mapping.input_line_count as u32) + 1;
executable_lines = Bitset::init_empty(line_count as usize)?;
lines_which_have_executed = Bitset::init_empty(line_count as usize)?;
line_hits = vec![0u32; line_count as usize];
```

It then resolves byte offsets through `parsed_mapping.find_mapping` or `cursor.move_to`, converts `point.original.lines.zero_based()` to `u32`, and uses that value directly:

```rust
executable_lines.set(line as usize);
lines_which_have_executed.set(line as usize);
line_hits_slice[line as usize] += 1;
```

No upper-bound check existed before the index or bitset update.

The reproduced path shows this is reachable with internal Bun sourcemaps:

- `src/sourcemap/Chunk.rs:396` writes `approximate_input_line_count` into the sourcemap header.
- `src/js_printer/lib.rs:7945` derives that value from `tree.approximate_newline_count`.
- `src/js_parser/lexer.rs:1341` increments the approximate count only for `\n`.
- `src/sourcemap/LineOffsetTable.rs:247` treats lone `\r`, U+2028, and U+2029 as line breaks when deriving original mappings.

An attacker-controlled file containing a lone `\r` before executed code can therefore produce an internal sourcemap with `input_line_count == 0` while a mapping points to original line `1`. Coverage allocates `line_hits` with length `1` and then indexes `line_hits_slice[1]`, panicking.

## Why This Is A Real Bug

The reproduced input demonstrates a mismatch between the sourcemap header line count and the line indexes emitted by mapping lookup. The panic does not require memory corruption or undefined behavior; safe Rust bounds checks terminate coverage generation when `line_hits_slice[line as usize]` is out of range. Because the affected code runs during coverage report generation, an attacker-controlled project file can reliably deny coverage reporting.

## Fix Requirement

Reject or skip sourcemap original line indexes where `line >= line_count` before any coverage vector indexing or bitset update.

## Patch Rationale

The patch adds an upper-bound guard immediately after converting the original sourcemap line index and before using it:

```rust
if line >= line_count {
    continue;
}
```

This is applied in both sourcemap mapping loops:

- Executed/basic block coverage path before `executable_lines.set`, `lines_which_have_executed.set`, and `line_hits_slice[line as usize] += 1`.
- Function block path before using the line to compute `min_line` and `max_line`.

Skipping out-of-range mappings preserves valid coverage data and prevents malformed sourcemaps from crashing report generation.

## Residual Risk

None

## Patch

```diff
diff --git a/src/sourcemap_jsc/CodeCoverage.rs b/src/sourcemap_jsc/CodeCoverage.rs
index e0895e7d47..0e900f7033 100644
--- a/src/sourcemap_jsc/CodeCoverage.rs
+++ b/src/sourcemap_jsc/CodeCoverage.rs
@@ -703,6 +703,9 @@ impl ByteRangeMapping {
 
                         let line: u32 =
                             u32::try_from(point.original.lines.zero_based()).expect("int cast");
+                        if line >= line_count {
+                            continue;
+                        }
 
                         executable_lines.set(line as usize);
                         if has_executed {
@@ -782,6 +785,9 @@ impl ByteRangeMapping {
 
                         let line: u32 =
                             u32::try_from(point.original.lines.zero_based()).expect("int cast");
+                        if line >= line_count {
+                            continue;
+                        }
                         min_line = min_line.min(line);
                         max_line = max_line.max(line);
                     }
```