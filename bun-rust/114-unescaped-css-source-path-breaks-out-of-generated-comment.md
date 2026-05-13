# Unescaped CSS Source Path Breaks Out Of Generated Comment

## Classification

Injection, medium severity. Confidence: certain.

## Affected Locations

`src/bundler/linker_context/postProcessCSSChunk.rs:77`

## Summary

In bundle mode with whitespace minification disabled, Bun emits a generated CSS comment before each CSS compile result. The comment included `sources[source_index].path.pretty` without escaping. A dependency author controlling a CSS filename could include `*/` in the path, terminate the generated comment early, and inject CSS rules into the bundled stylesheet.

## Provenance

Verified by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- Bundling mode is enabled.
- Whitespace minification is disabled.
- The compile result has a valid source index.
- An attacker can influence a dependency CSS source path, such as through a malicious package filename.

## Proof

`post_process_css_chunk` emitted the following sequence:

```css
/* <source path> */
```

The source path came from `sources[source_index as usize].path.pretty` and was written directly into the stylesheet comment.

A malicious package path such as:

```text
node_modules/evil/*/body{--pwn:1}/*/x.css
```

produced:

```css
/* node_modules/evil/*/body{--pwn:1}/*/x.css */
```

CSS parsing closes the comment at the first `*/`, parses `body{--pwn:1}` as stylesheet content, and then treats the following `/*` as a new comment opener. The generated closing suffix then closes that comment. The attacker-controlled filename bytes therefore escape the intended comment and become active CSS.

The reproduced data flow confirms the source index and path are valid and attacker-influenced:

- `src/bundler/linker_context/generateCompileResultForCssChunk.rs:187` propagates the source index into the CSS compile result.
- `src/bundler/linker_context/generateCompileResultForCssChunk.rs:228` passes that compile result to post-processing.
- `src/bundler/ParseTask.rs:2377` populates the source path from `file_path.pretty`.
- `src/bundler/ParseTask.rs:2381` does not apply CSS-comment escaping.

## Why This Is A Real Bug

The generated source comment is emitted into the final stylesheet, and CSS comments are syntactically terminated by `*/`. Because the source path was inserted literally, `*/` in a filename changed parser state from comment content to stylesheet content. This is not only malformed output: it allows attacker-controlled bytes from a package path to become active CSS rules in the bundle.

## Fix Requirement

Do not insert unescaped source paths into CSS comments. The generated comment must either omit source paths or encode them so that comment terminators such as `*/` cannot appear in the emitted CSS comment body.

## Patch Rationale

The patch removes the attacker-controlled path from the generated comment and emits a fixed inert comment:

```css
/* */
```

This preserves the structural separator and line accounting behavior while eliminating the injection sink. Since no path bytes are written into the CSS comment, `*/` in filenames can no longer terminate the generated comment or inject stylesheet rules.

## Residual Risk

None

## Patch

```diff
diff --git a/src/bundler/linker_context/postProcessCSSChunk.rs b/src/bundler/linker_context/postProcessCSSChunk.rs
index e4dd36f59d..c0f0a73ec0 100644
--- a/src/bundler/linker_context/postProcessCSSChunk.rs
+++ b/src/bundler/linker_context/postProcessCSSChunk.rs
@@ -69,16 +69,8 @@ pub fn post_process_css_chunk(
                 line_offset.advance(b"\n");
             }
 
-            let pretty: &[u8] = sources[source_index as usize].path.pretty;
-
-            j.push_static(b"/* ");
-            line_offset.advance(b"/* ");
-
-            j.push_static(pretty);
-            line_offset.advance(pretty);
-
-            j.push_static(b" */\n");
-            line_offset.advance(b" */\n");
+            j.push_static(b"/* */\n");
+            line_offset.advance(b"/* */\n");
         }
 
         if !compile_result.code().is_empty() {
```