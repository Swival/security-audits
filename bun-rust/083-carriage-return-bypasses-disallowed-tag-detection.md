# Carriage Return Bypasses Disallowed Tag Detection

## Classification

Security control failure, high severity.

## Affected Locations

`src/md/html_renderer.rs:764`

## Summary

The GFM tag filter failed to recognize disallowed HTML tags when the tag name was followed by a carriage return (`\r`). As a result, raw HTML such as `<script\r>alert(1)</script>` could pass through unescaped even when `tag_filter` was enabled.

## Provenance

Verified from supplied source, reproducer, and patch evidence.

Reported by Swival.dev Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

`tag_filter` is enabled and attacker-controlled raw HTML reaches the markdown HTML renderer.

## Proof

`TextType::Html` invokes both `update_tag_filter_raw_depth(content)` and `write_html_with_tag_filter(content)`.

Both paths depend on `is_disallowed_tag`, which delegates tag-name recognition to `match_tag_name_ci`.

For input:

```html
<script>alert(1)</script>
```

`match_tag_name_ci` case-insensitively matches `script`, then checks the next byte as the tag-name delimiter. Before the patch, accepted delimiters were only:

```rust
b'>' | b' ' | b'\t' | b'\n' | b'/'
```

Because `b'\r'` was omitted, `is_disallowed_tag` returned `false`. Consequently, `write_html_with_tag_filter` did not replace the leading `<` with `&lt;`, and the raw script tag was emitted unchanged.

## Why This Is A Real Bug

Carriage return is valid whitespace in the surrounding markdown/HTML parsing model, and the project’s helpers classify CR as whitespace. The tag filter is intended to reject GFM-disallowed tags followed by whitespace, but its delimiter check treated LF as whitespace while excluding CR.

This created a deterministic fail-open condition: a disallowed tag followed by `\r` bypassed the filter despite matching a blocked tag name.

## Fix Requirement

Treat carriage return (`\r`) as a valid tag-name whitespace delimiter in `match_tag_name_ci`.

## Patch Rationale

The patch adds `b'\r'` to the accepted delimiter set after a matched disallowed tag name:

```rust
matches!(content[end], b'>' | b' ' | b'\t' | b'\n' | b'\r' | b'/')
```

This aligns the tag-filter delimiter logic with whitespace handling elsewhere and ensures `<script\r...>` is classified as a disallowed tag.

## Residual Risk

None

## Patch

```diff
diff --git a/src/md/html_renderer.rs b/src/md/html_renderer.rs
index 521b5885c0..4cc0bf6859 100644
--- a/src/md/html_renderer.rs
+++ b/src/md/html_renderer.rs
@@ -762,7 +762,7 @@ fn match_tag_name_ci(content: &[u8], pos: usize, tag: &[u8]) -> bool {
     if end >= content.len() {
         return true;
     }
-    matches!(content[end], b'>' | b' ' | b'\t' | b'\n' | b'/')
+    matches!(content[end], b'>' | b' ' | b'\t' | b'\n' | b'\r' | b'/')
 }
 
 /// Find an entity in text starting at `start`. Delegates to helpers.findEntity.
```