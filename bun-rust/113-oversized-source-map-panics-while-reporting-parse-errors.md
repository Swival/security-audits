# Oversized Source Map Panics While Reporting Parse Errors

## Classification

Denial of service, medium severity.

## Affected Locations

`src/sourcemap/Mapping.rs:590`

## Summary

Malformed source map mappings can make the parser panic instead of returning `ParseResult::Fail` when the malformed segment appears after more than `i32::MAX` bytes of mapping input. The panic occurs while constructing `Loc.start` for parse-error reporting using a fallible `usize` to `i32` conversion followed by `expect("int cast")`.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Attacker controls or can supply a source map, such as through a malicious dependency.
- The `mappings` input exceeds `i32::MAX` bytes before a malformed segment.
- The malformed segment reaches an error path that computes `Loc.start` from `bytes.len() - remain.len()`.

## Proof

The parser advances through source map mappings using `bytes` and `remain`. On parse errors, it computes the byte offset as:

```rust
i32::try_from(bytes.len() - remain.len()).expect("int cast")
```

This is used in multiple error paths, including the `InvalidNameIndexDelta` path near `src/sourcemap/Mapping.rs:590`.

A reproduced trigger advances past 2GB of attacker-controlled mapping data using repeated valid empty/generated-column-only segments, then ends with a malformed segment. The final malformed segment decodes generated column `0`, source index `0`, and original-line delta `-1`, causing the invalid original line error path to construct `Loc.start`. Because the offset is greater than `i32::MAX`, `i32::try_from(...)` returns `Err`, and `expect("int cast")` panics.

External source maps are reachable from `.map` files through `src/sourcemap/lib.rs:727` and `src/sourcemap/lib.rs:732`. The extracted mappings slice is passed into `mapping::parse` at `src/sourcemap/lib.rs:1199` without a mapping-length cap.

## Why This Is A Real Bug

Invalid source maps are expected to return `ParseResult::Fail` and be handled as warnings or errors. In this case, attacker-sized input causes diagnostic offset construction itself to panic, bypassing normal parse-failure handling. A malicious dependency author can therefore abort a build or runtime worker that processes the supplied source map.

## Fix Requirement

`Loc.start` construction must not panic for attacker-controlled input sizes. The parser must either widen the location type or safely saturate/truncate offsets that exceed `i32::MAX`.

## Patch Rationale

The patch replaces every parse-error `Loc.start` conversion in `src/sourcemap/Mapping.rs` from:

```rust
i32::try_from(bytes.len() - remain.len()).expect("int cast")
```

to:

```rust
i32::try_from(bytes.len() - remain.len()).unwrap_or(i32::MAX)
```

This preserves exact offsets within the representable `i32` range and saturates oversized offsets to `i32::MAX`. The parser now returns the intended `ParseResult::Fail` instead of panicking when reporting malformed oversized mappings.

## Residual Risk

None

## Patch

```diff
diff --git a/src/sourcemap/Mapping.rs b/src/sourcemap/Mapping.rs
index 03eab1107f..5271a789ba 100644
--- a/src/sourcemap/Mapping.rs
+++ b/src/sourcemap/Mapping.rs
@@ -551,7 +551,7 @@ pub fn parse(
                 err: err!("MissingGeneratedColumnValue"),
                 value: generated.columns.zero_based(),
                 loc: Loc {
-                    start: i32::try_from(bytes.len() - remain.len()).expect("int cast"),
+                    start: i32::try_from(bytes.len() - remain.len()).unwrap_or(i32::MAX),
                 },
             });
         }
@@ -565,7 +565,7 @@ pub fn parse(
                 err: err!("InvalidGeneratedColumnValue"),
                 value: generated.columns.zero_based(),
                 loc: Loc {
-                    start: i32::try_from(bytes.len() - remain.len()).expect("int cast"),
+                    start: i32::try_from(bytes.len() - remain.len()).unwrap_or(i32::MAX),
                 },
             });
         }
@@ -598,7 +598,7 @@ pub fn parse(
                 msg: b"Invalid source index delta",
                 err: err!("InvalidSourceIndexDelta"),
                 loc: Loc {
-                    start: i32::try_from(bytes.len() - remain.len()).expect("int cast"),
+                    start: i32::try_from(bytes.len() - remain.len()).unwrap_or(i32::MAX),
                 },
                 ..Default::default()
             });
@@ -611,7 +611,7 @@ pub fn parse(
                 err: err!("InvalidSourceIndexValue"),
                 value: source_index,
                 loc: Loc {
-                    start: i32::try_from(bytes.len() - remain.len()).expect("int cast"),
+                    start: i32::try_from(bytes.len() - remain.len()).unwrap_or(i32::MAX),
                 },
             });
         }
@@ -624,7 +624,7 @@ pub fn parse(
                 msg: b"Missing original line",
                 err: err!("MissingOriginalLine"),
                 loc: Loc {
-                    start: i32::try_from(bytes.len() - remain.len()).expect("int cast"),
+                    start: i32::try_from(bytes.len() - remain.len()).unwrap_or(i32::MAX),
                 },
                 ..Default::default()
             });
@@ -637,7 +637,7 @@ pub fn parse(
                 err: err!("InvalidOriginalLineValue"),
                 value: original.lines.zero_based(),
                 loc: Loc {
-                    start: i32::try_from(bytes.len() - remain.len()).expect("int cast"),
+                    start: i32::try_from(bytes.len() - remain.len()).unwrap_or(i32::MAX),
                 },
             });
         }
@@ -651,7 +651,7 @@ pub fn parse(
                 err: err!("MissingOriginalColumnValue"),
                 value: original.columns.zero_based(),
                 loc: Loc {
-                    start: i32::try_from(bytes.len() - remain.len()).expect("int cast"),
+                    start: i32::try_from(bytes.len() - remain.len()).unwrap_or(i32::MAX),
                 },
             });
         }
@@ -663,7 +663,7 @@ pub fn parse(
                 err: err!("InvalidOriginalColumnValue"),
                 value: original.columns.zero_based(),
                 loc: Loc {
-                    start: i32::try_from(bytes.len() - remain.len()).expect("int cast"),
+                    start: i32::try_from(bytes.len() - remain.len()).unwrap_or(i32::MAX),
                 },
             });
         }
@@ -688,7 +688,7 @@ pub fn parse(
                             err: err!("InvalidNameIndexDelta"),
                             value: i32::from(c),
                             loc: Loc {
-                                start: i32::try_from(bytes.len() - remain.len()).expect("int cast"),
+                                start: i32::try_from(bytes.len() - remain.len()).unwrap_or(i32::MAX),
                             },
                         });
                     }
@@ -702,8 +702,7 @@ pub fn parse(
                                     msg: b"Out of memory",
                                     err: err!("OutOfMemory"),
                                     loc: Loc {
-                                        start: i32::try_from(bytes.len() - remain.len())
-                                            .expect("int cast"),
+                                        start: i32::try_from(bytes.len() - remain.len()).unwrap_or(i32::MAX),
                                     },
                                     ..Default::default()
                                 });
```