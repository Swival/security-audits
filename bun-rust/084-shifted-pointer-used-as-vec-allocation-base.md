# shifted pointer used as Vec allocation base

## Classification

High severity memory corruption.

Confidence: certain.

## Affected Locations

`src/bundler/linker_context/prepareCssAstsForChunk.rs:384`

## Summary

The CSS chunk preparation path shallow-copied a stylesheet, then attempted to strip leading `@import` / ignored rules by constructing a `Vec` from an interior pointer into the original allocation. Rust `Vec` ownership requires the pointer passed to `Vec::from_raw_parts` to be the original allocation base. Using `old_ptr.add(prefix_end)` violates that invariant and can corrupt memory when the `Vec` is later used or dropped.

## Provenance

Verified finding from Swival.dev Security Scanner: https://swival.dev

## Preconditions

- The bundler processes attacker-controlled CSS as a chunk `source_index` entry.
- The CSS source begins with one or more `@import` or ignored rules before the first style rule.
- No leading `@layer` statement rules are preserved, so `dropped > 0` and `layer_count == 0`.

## Proof

In `CssImportOrderKind::SourceIndex`, the original stylesheet is shallow-copied into `css_chunk.asts[i]` with `core::ptr::read(original_stylesheet)`. This means `ast.rules.v` aliases the original stylesheet rule buffer.

When the prefix scan finds leading dropped rules and no preserved layer statements, the fast path computes a tail slice and replaces the vector with:

```rust
Vec::from_raw_parts(old_ptr.add(prefix_end), tail_len, old_cap - prefix_end)
```

Because `prefix_end > 0`, `old_ptr.add(prefix_end)` is an interior pointer, not the allocation base. A minimal equivalent shifted-`Vec::from_raw_parts` runtime check aborts on drop with `free(): invalid pointer`, confirming the invalid allocation-base behavior.

## Why This Is A Real Bug

`Vec::from_raw_parts` has a strict safety requirement: its pointer must be the pointer originally returned by the allocator for that allocation. The vulnerable code intentionally passes a shifted pointer derived from attacker-controlled CSS structure. Later `Vec` drop or reallocation can free or operate on a non-base pointer, which is undefined behavior and memory corruption in the bundler worker.

## Fix Requirement

Do not create an owning `Vec` from a shifted interior pointer. Preserve any offset separately in a non-owning view, or allocate a fresh `Vec` containing the retained tail rules.

## Patch Rationale

The patch removes the shifted-pointer fast path. For the `layer_count == 0` case, it now builds a fresh `BundlerCssRuleList`, shallow-copies only the retained tail rules into that new list, leaks the shallow-copied aliased header to preserve Zig overwrite semantics, and installs the fresh list. The resulting `Vec` owns an allocation whose pointer is the allocation base.

## Residual Risk

None

## Patch

```diff
diff --git a/src/bundler/linker_context/prepareCssAstsForChunk.rs b/src/bundler/linker_context/prepareCssAstsForChunk.rs
index 0a060f7f35..e9fe4bfa07 100644
--- a/src/bundler/linker_context/prepareCssAstsForChunk.rs
+++ b/src/bundler/linker_context/prepareCssAstsForChunk.rs
@@ -389,26 +389,21 @@ fn prepare_css_asts_for_chunk_impl(c: &mut LinkerContext, chunk: &mut Chunk, bum
                             // Prefix is all "@layer" (or empty). Nothing to
                             // strip — leave `ast.rules.v` untouched.
                         } else if layer_count == 0 {
-                            // Fast path: no "@layer" statements to preserve,
-                            // reslice the copied header forward. This does
-                            // not touch the backing array.
-                            let original_len = original_rules.len();
-                            let tail_len = original_len - prefix_end;
-                            // SAFETY: `ast.rules.v` is a shallow-copied `Vec` header
-                            // aliasing the source stylesheet's backing buffer (see
-                            // `ptr::read` above). Advancing ptr/len/cap mirrors Zig's
-                            // ArrayListUnmanaged reslice; the buffer is arena-owned
-                            // and never freed via this view.
-                            unsafe {
-                                let old_ptr = ast.rules.v.as_mut_ptr();
-                                let old_cap = ast.rules.v.capacity();
-                                core::mem::forget(core::mem::take(&mut ast.rules.v));
-                                ast.rules.v = Vec::from_raw_parts(
-                                    old_ptr.add(prefix_end),
-                                    tail_len,
-                                    old_cap - prefix_end,
-                                );
+                            // No "@layer" statements to preserve. Copy the
+                            // tail into a fresh list so Vec ownership still
+                            // starts at the allocation base.
+                            let mut new_rules = BundlerCssRuleList::default();
+                            for rule in &original_rules[prefix_end..] {
+                                // SAFETY: Zig by-value copy of arena-backed rule.
+                                new_rules.v.push(unsafe { core::ptr::read(rule) });
                             }
+                            // `ast.rules` is the shallow-copied header aliasing the
+                            // source stylesheet's arena buffer (see `ptr::read` above).
+                            // Dropping it would `drop_in_place` the aliased rules and
+                            // free the shared backing array. Leak the header (Zig
+                            // semantics: bitwise overwrite) before installing the
+                            // freshly-allocated list.
+                            core::mem::forget(core::mem::replace(&mut ast.rules, new_rules));
                         } else {
                             // Interleaved case: allocate a fresh rules list
                             // so we don't mutate the shared backing array.
```