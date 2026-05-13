# Malformed Inline Sourcemap URL Panics Parser

## Classification

Denial of service, medium severity, confidence certain.

## Affected Locations

`src/sourcemap/lib.rs:1024`

## Summary

A malformed inline sourcemap URL of `data:application/json;base64` without the required comma separator reaches `parse_url` and causes a Rust slice-bounds panic. An attacker who controls JavaScript source text can crash the process when inline sourcemap loading is attempted.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

Inline sourcemap loading is attempted for attacker-controlled source text.

## Proof

The reachable input is a trailing sourcemap comment such as:

```js
//# sourceMappingURL=data:application/json;base64
```

Reachability:

- `get_source_map_impl` reads the provider source text.
- `find_source_mapping_url_u8` or `find_source_mapping_url_u16` extracts the trailing `sourceMappingURL` comment.
- The extracted URL bytes are passed to `parse_url`.

Failing path in `parse_url`:

- The input starts with `data:application/json`.
- The byte after the prefix is `;`, so the data URL encoding branch is entered.
- `after` is `base64`.
- No comma exists, so the old code computed `encoding` as `base64`.
- `encoding == b"base64"` passed.
- The old code sliced from `DATA_PREFIX.len() + b";base64,".len()`, which is one byte past the end for `data:application/json;base64`.
- Rust bounds checking panicked, terminating the process.

## Why This Is A Real Bug

The bug is not theoretical because the malformed URL is accepted far enough to enter the base64 branch, and the unchecked slice is performed before any recoverable parse error is returned. Rust panics on out-of-bounds slice indices, so attacker-controlled source text can trigger process termination during sourcemap parsing.

## Fix Requirement

Require a comma separator before slicing base64 payload data. If the comma is missing, reject the URL as an unsupported format instead of slicing past the end.

## Patch Rationale

The patch changes `parse_url` to explicitly search for a comma in the data URL metadata segment. If no comma is present, parsing exits through the existing unsupported-format path. If a comma is present, `encoding` is taken from bytes before the comma and `base64_data` is taken from `after[comma + 1..]`, which is bounded by the actual slice containing the comma.

This removes the panic condition and preserves valid inline base64 sourcemap handling.

## Residual Risk

None

## Patch

```diff
diff --git a/src/sourcemap/lib.rs b/src/sourcemap/lib.rs
index 6ab4216727..cb6abae4d9 100644
--- a/src/sourcemap/lib.rs
+++ b/src/sourcemap/lib.rs
@@ -1080,12 +1080,14 @@ pub fn parse_url(
                 match source[DATA_PREFIX.len()] {
                     b';' => {
                         let after = &source[DATA_PREFIX.len() + 1..];
-                        let encoding =
-                            &after[..after.iter().position(|&b| b == b',').unwrap_or(after.len())];
+                        let Some(comma) = after.iter().position(|&b| b == b',') else {
+                            break 'try_data_url;
+                        };
+                        let encoding = &after[..comma];
                         if encoding != b"base64" {
                             break 'try_data_url;
                         }
-                        let base64_data = &source[DATA_PREFIX.len() + b";base64,".len()..];
+                        let base64_data = &after[comma + 1..];
 
                         let len = bun_base64::decode_len(base64_data);
                         let bytes = arena.alloc_slice_fill_default::<u8>(len);
```