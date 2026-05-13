# Invalid UTF-8 Glob Panics Absolute-Path Slicing

## Classification

Denial of service, medium severity.

## Affected Locations

- `src/glob/GlobWalker.rs:519`
- `src/glob/GlobWalker.rs:1510`
- `src/glob/GlobWalker.rs:2196`
- `src/glob/GlobWalker.rs:2243`

## Summary

An attacker-controlled absolute glob byte pattern ending in a truncated UTF-8 leading byte can make `build_pattern_components()` record an end offset beyond `pattern.len()`. `Iterator::init()` later uses that offset to slice `self.walker.pattern`, causing an out-of-bounds panic before filesystem handling begins.

## Provenance

Reported and reproduced from Swival.dev Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The glob API accepts attacker-controlled absolute byte patterns.
- The caller permits non-UTF-8 byte patterns.
- The attacker can supply a pattern ending with an invalid or truncated UTF-8 leading byte, such as `b"/tmp/\xE0"`.

## Proof

Reproducer path:

- `GlobWalker::init_with_cwd()` stores the raw pattern and calls `build_pattern_components()` at `src/glob/GlobWalker.rs:1510`.
- `build_pattern_components()` computes `width = strings::wtf8_byte_sequence_length(c)` at `src/glob/GlobWalker.rs:2196`.
- For a final byte `0xE0`, `width == 3`, but only one byte remains in the pattern.
- After the scan loop, `i` is reduced to `len - 1`.
- The final literal component records `end_byte_of_basename_excluding_special_syntax = i + width` at `src/glob/GlobWalker.rs:2243`.
- For `b"/tmp/\xE0"`, this produces an offset greater than `pattern.len()`.
- `Iterator::init()` then slices `&self.walker.pattern[0..end_byte]` for absolute patterns at `src/glob/GlobWalker.rs:519`.
- Rust panics on the out-of-bounds slice.

## Why This Is A Real Bug

The panic is reachable from input parsing alone. No filesystem race, directory contents, or successful open is required. A lower-privileged actor who can submit glob patterns can crash the worker handling the request with a single malformed absolute byte pattern, creating attacker-controlled denial of service.

## Fix Requirement

Any byte offset derived from UTF-8 sequence width must not exceed the underlying byte slice length. The basename end offset used for later slicing must be clamped to `pattern.len()` or invalid UTF-8 byte patterns must be rejected before offsets are stored.

## Patch Rationale

The patch records `pattern_len` once and clamps every assignment to `end_byte_of_basename_excluding_special_syntax` with `(i + width).min(pattern_len)`. This preserves existing behavior for valid patterns while preventing malformed trailing byte sequences from producing offsets outside the pattern buffer.

## Residual Risk

None

## Patch

```diff
diff --git a/src/glob/GlobWalker.rs b/src/glob/GlobWalker.rs
index f175f6298f..6b38d1f09c 100644
--- a/src/glob/GlobWalker.rs
+++ b/src/glob/GlobWalker.rs
@@ -2185,6 +2185,7 @@ impl<A: Accessor, const SENTINEL: bool> GlobWalker<A, SENTINEL> {
         basename_excluding_special_syntax_component_idx: &mut u32,
     ) -> Result<(), AllocError> {
         let mut start_byte: u32 = 0;
+        let pattern_len: u32 = u32::try_from(pattern.len()).expect("int cast");
 
         let mut prev_is_backslash = false;
         let mut saw_special = false;
@@ -2210,7 +2211,8 @@ impl<A: Accessor, const SENTINEL: bool> GlobWalker<A, SENTINEL> {
                     if !saw_special {
                         *basename_excluding_special_syntax_component_idx =
                             u32::try_from(pattern_components.len()).expect("int cast");
-                        *end_byte_of_basename_excluding_special_syntax = i + width;
+                        *end_byte_of_basename_excluding_special_syntax =
+                            (i + width).min(pattern_len);
                     }
                     pattern_components.push(component);
                 }
@@ -2240,13 +2242,15 @@ impl<A: Accessor, const SENTINEL: bool> GlobWalker<A, SENTINEL> {
             if !saw_special {
                 *basename_excluding_special_syntax_component_idx =
                     u32::try_from(pattern_components.len()).expect("int cast");
-                *end_byte_of_basename_excluding_special_syntax = i + width;
+                *end_byte_of_basename_excluding_special_syntax =
+                    (i + width).min(pattern_len);
             }
             pattern_components.push(component);
         } else if !saw_special {
             *basename_excluding_special_syntax_component_idx =
                 u32::try_from(pattern_components.len()).expect("int cast");
-            *end_byte_of_basename_excluding_special_syntax = i + width;
+            *end_byte_of_basename_excluding_special_syntax =
+                (i + width).min(pattern_len);
         }
 
         Ok(())
```