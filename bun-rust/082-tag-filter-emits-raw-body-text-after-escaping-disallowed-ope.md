# tag filter emits raw body text after escaping disallowed opener

## Classification

High severity injection.

Confidence: certain.

## Affected Locations

`src/md/html_renderer.rs:432`

## Summary

When `tag_filter` is enabled, disallowed raw HTML openers such as `<script>` are partially escaped, but body text inside the filtered raw zone was emitted without HTML escaping. An attacker-controlled Markdown document could therefore place active HTML in the body of a disallowed raw HTML block and have that markup emitted into rendered HTML.

## Provenance

Verified and patched finding from Swival.dev Security Scanner: https://swival.dev

## Preconditions

- `tag_filter` is enabled.
- Rendered Markdown output is embedded as HTML.
- Attacker can author Markdown content.

## Proof

A reachable trigger is:

```md
<script>
<svg/onload=alert(1)>
</script>
```

Reachability and propagation:

- `<script>` starts a type-1 raw HTML block in `src/md/line_analysis.rs:220`.
- The raw HTML block continues until `</script>` via `src/md/line_analysis.rs:284`.
- Raw HTML block lines are emitted as `TextType::Html` in `src/md/render_blocks.rs:49`.
- `HtmlRenderer::text` routes `TextType::Html` through `update_tag_filter_raw_depth` and `write_html_with_tag_filter` when `tag_filter` is enabled.
- The disallowed `<script>` opener has only its leading `<` rewritten to `&lt;`.
- While `tag_filter_raw_depth` remains nonzero, non-HTML text previously used `self.write(content)` instead of `write_html_escaped(content)`.

Resulting output included active attacker-controlled HTML:

```html
&lt;script>
<svg/onload=alert(1)>
&lt;/script>
```

## Why This Is A Real Bug

The tag filter intends to neutralize disallowed raw HTML tags. However, after escaping the disallowed opener, the renderer kept a raw-depth state and wrote subsequent non-HTML text directly to the output. Because Markdown raw HTML block content can contain attacker-controlled markup, this allowed active HTML such as `<svg/onload=alert(1)>` to survive rendering and execute when embedded in a page.

## Fix Requirement

Escape all non-HTML text while inside `tag_filter_raw_depth` disallowed zones.

## Patch Rationale

The vulnerable branch special-cased `tag_filter && tag_filter_raw_depth > 0` and wrote content raw. Removing that branch makes all ordinary text use `write_html_escaped(content)`, including text inside filtered disallowed-tag zones. This preserves the renderer’s normal escaping behavior and prevents attacker-controlled body text from becoming active HTML.

## Residual Risk

None

## Patch

```diff
diff --git a/src/md/html_renderer.rs b/src/md/html_renderer.rs
index 521b5885c0..e715910b06 100644
--- a/src/md/html_renderer.rs
+++ b/src/md/html_renderer.rs
@@ -428,12 +428,7 @@ impl<'src> HtmlRenderer<'src> {
                 }
             }
             _ => {
-                // When inside a tag-filtered disallowed tag, emit text as raw
-                if self.tag_filter && self.tag_filter_raw_depth > 0 {
-                    self.write(content);
-                } else {
-                    self.write_html_escaped(content);
-                }
+                self.write_html_escaped(content);
             }
         }
     }
```