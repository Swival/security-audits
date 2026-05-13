# Quadratic Reference Definition Duplicate Checks

## Classification

Denial of service, medium severity, certain confidence.

## Affected Locations

- `src/md/blocks.rs:951`
- `src/md/blocks.rs:985`
- `src/md/blocks.rs:991`
- `src/md/ref_defs.rs:414`

## Summary

Markdown reference-definition parsing used a linear scan over all previously accepted reference definitions to enforce “first definition wins.” An attacker-controlled document with many unique reference labels caused deterministic quadratic CPU work during parsing.

The patch adds a parser-owned `HashSet<Box<[u8]>>` of normalized reference labels and uses it for duplicate detection in both reference-definition ingestion paths.

## Provenance

Verified from the supplied source, reproducer summary, and patch.

Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- The parser processes attacker-controlled Markdown.
- The attacker can include many unique link reference definitions in one parsed document.

## Proof

`process_doc` always calls `build_ref_def_hashtable` after block parsing. Separately, `end_current_block` calls `consume_ref_defs_from_current_block` for setext-style blocks beginning with `[`.

In `consume_ref_defs_from_current_block`, each parsed reference definition:

- normalizes an attacker-controlled label at `src/md/blocks.rs:985`
- scans `self.ref_defs.iter()` for an existing label at `src/md/blocks.rs:991`
- pushes a new definition when no duplicate exists at `src/md/blocks.rs:998`

For `N` unique labels, `already_exists` remains false, so the loop performs:

```text
0 + 1 + 2 + ... + (N - 1)
```

comparisons.

The same duplicate-scan pattern existed in `build_ref_def_hashtable` at `src/md/ref_defs.rs:414`, which is always reached by `process_doc`.

The 999-byte label cap only limits individual label length. It does not cap the number of reference definitions, so it does not prevent the quadratic behavior.

## Why This Is A Real Bug

The vulnerable work is reachable from one Markdown document supplied to the parser. Unique labels avoid early duplicate exits, forcing each new definition to compare against all previously stored definitions.

This creates deterministic `O(N^2)` CPU consumption in parsing, enabling practical denial of service when untrusted Markdown is accepted from clients, files, or backend inputs.

## Fix Requirement

Duplicate reference-label checks must be indexed by normalized label and run in expected `O(1)` time per definition.

Both reference-definition ingestion paths must share the same duplicate state so “first definition wins” semantics remain consistent.

## Patch Rationale

The patch adds:

```rust
pub ref_def_labels: std::collections::HashSet<Box<[u8]>>
```

to `Parser`, initialized in `Parser::new`.

Both duplicate-check sites now:

- convert the normalized label to `Box<[u8]>`
- insert it into `self.ref_def_labels`
- push the `RefDef` only when insertion succeeds

This preserves first-definition-wins behavior while replacing the prior linear scan with hash-set lookup.

## Residual Risk

None

## Patch

```diff
diff --git a/src/md/blocks.rs b/src/md/blocks.rs
index 918cf26bed..460065e9ec 100644
--- a/src/md/blocks.rs
+++ b/src/md/blocks.rs
@@ -988,16 +988,10 @@ impl Parser<'_> {
             }
 
             // First definition wins
-            let mut already_exists = false;
-            for existing in self.ref_defs.iter() {
-                if existing.label[..] == norm_label[..] {
-                    already_exists = true;
-                    break;
-                }
-            }
-            if !already_exists {
+            let label = norm_label.into_boxed_slice();
+            if self.ref_def_labels.insert(label.clone()) {
                 self.ref_defs.push(crate::ref_defs::RefDef {
-                    label: norm_label.into_boxed_slice(),
+                    label,
                     dest: dest_dupe,
                     title: title_dupe,
                 });
diff --git a/src/md/parser.rs b/src/md/parser.rs
index f0c81b4451..f7d6a294eb 100644
--- a/src/md/parser.rs
+++ b/src/md/parser.rs
@@ -93,6 +93,7 @@ pub struct Parser<'a> {
 
     // Ref defs
     pub ref_defs: Vec<RefDef>,
+    pub ref_def_labels: std::collections::HashSet<Box<[u8]>>,
 
     // State
     pub last_line_has_list_loosening_effect: bool,
@@ -196,6 +197,7 @@ impl<'a> Parser<'a> {
             table_col_count: 0,
             table_alignments: [Align::Default; TABLE_MAXCOLCOUNT as usize],
             ref_defs: Vec::new(),
+            ref_def_labels: std::collections::HashSet::new(),
             last_line_has_list_loosening_effect: false,
             last_list_item_starts_with_two_blank_lines: false,
             max_ref_def_output: (16 * (size as u64)).min(1024 * 1024).min(u32::MAX as u64),
diff --git a/src/md/ref_defs.rs b/src/md/ref_defs.rs
index 348ae5695b..e684410d0a 100644
--- a/src/md/ref_defs.rs
+++ b/src/md/ref_defs.rs
@@ -411,19 +411,13 @@ impl Parser<'_> {
                 if norm_label.is_empty() {
                     break; // whitespace-only labels are invalid
                 }
-                let mut already_exists = false;
-                for existing in self.ref_defs.iter() {
-                    if existing.label[..] == norm_label[..] {
-                        already_exists = true;
-                        break;
-                    }
-                }
-                if !already_exists {
+                let label = norm_label.into_boxed_slice();
+                if self.ref_def_labels.insert(label.clone()) {
                     // Dupe dest and title since they point into self.buffer which gets reused
                     let dest_dupe: Box<[u8]> = Box::from(result.dest);
                     let title_dupe: Box<[u8]> = Box::from(result.title);
                     self.ref_defs.push(RefDef {
-                        label: norm_label.into_boxed_slice(),
+                        label,
                         dest: dest_dupe,
                         title: title_dupe,
                     });
```