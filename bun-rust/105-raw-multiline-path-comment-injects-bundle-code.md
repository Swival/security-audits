# Raw Multiline Path Comment Injects Bundle Code

## Classification

Code execution; high severity; confidence certain.

## Affected Locations

`src/bundler/linker_context/postProcessJSChunk.rs:606`

## Summary

When bundling with comments enabled and non-minified whitespace, source paths are emitted into generated JavaScript comments before file contents. Paths containing newlines select multiline comment output, but the raw path is copied without escaping `*/`. A malicious dependency package can place `*/\n<js>\n/*` in a source path, close the generated comment, inject JavaScript, and reopen a comment to absorb the bundler’s trailing terminator.

## Provenance

Verified and patched from the supplied reproduced finding. Scanner provenance: [Swival.dev Security Scanner](https://swival.dev).

## Preconditions

- Bundling mode is enabled.
- Comments are shown.
- Whitespace is not minified.
- An attacker can influence a bundled source path, such as through a malicious dependency package.

## Proof

The vulnerable path emission logic selected `CommentType::Multiline` when `pretty` contained a newline or non-ASCII byte, then emitted:

```js
/* <raw pretty> */
```

Because `pretty` was written directly, a POSIX package path such as:

```text
*/
globalThis.pwned=1
/*.js
```

could produce generated bundle output equivalent to:

```js
/* node_modules/evil/*/
globalThis.pwned=1
/*.js */
```

`globalThis.pwned=1` is no longer inside a comment and executes when the generated bundle runs.

The attacker-controlled path is reachable through package metadata and resolution: package `main` strings are accepted, joined/resolved as file paths, prettified without sanitizing newlines or comment delimiters, copied into `Source.path.pretty`, and later emitted in `post_process_js_chunk`.

## Why This Is A Real Bug

The emitted source path is part of executable JavaScript output. JavaScript block comments terminate on the first `*/`, and the original code did not escape or quote that delimiter. Under the stated bundling options, dependency-controlled path bytes can therefore alter generated JavaScript syntax and introduce executable statements.

## Fix Requirement

Never place raw source paths inside a JavaScript block comment. Source path comments must be emitted in a form where newlines, comment terminators, and other special bytes cannot terminate the comment or become executable JavaScript.

## Patch Rationale

The patch removes multiline block-comment emission for source paths. It always starts the filename annotation as a single-line comment:

```js
// 
```

For paths that previously required multiline handling, it serializes the path with `js_printer::quote_for_json`, producing a safe quoted representation where embedded newlines and dangerous delimiters are data inside the quoted string text. For ordinary single-line ASCII paths, it preserves direct output. The annotation is always terminated with a single newline.

This prevents `*/` from having syntactic meaning because the path is no longer inside a block comment, and encoded newlines do not break the single-line comment.

## Residual Risk

None

## Patch

```diff
diff --git a/src/bundler/linker_context/postProcessJSChunk.rs b/src/bundler/linker_context/postProcessJSChunk.rs
index 6d29cc03a9..61ef578c6c 100644
--- a/src/bundler/linker_context/postProcessJSChunk.rs
+++ b/src/bundler/linker_context/postProcessJSChunk.rs
@@ -670,20 +670,23 @@ pub fn post_process_js_chunk(
                 line_offset.advance(b"  ");
             }
 
+            j.push_static(b"// ");
+            line_offset.advance(b"// ");
+
             match comment_type {
                 CommentType::Multiline => {
-                    j.push_static(b"/* ");
-                    line_offset.advance(b"/* ");
+                    let mut buf = MutableString::init_empty();
+                    let _ = js_printer::quote_for_json(pretty, &mut buf, true);
+                    let pretty = buf.to_default_owned();
+                    line_offset.advance(&pretty);
+                    j.push_owned(pretty);
                 }
                 CommentType::Single => {
-                    j.push_static(b"// ");
-                    line_offset.advance(b"// ");
+                    j.push_static(pretty);
+                    line_offset.advance(pretty);
                 }
             }
 
-            j.push_static(pretty);
-            line_offset.advance(pretty);
-
             if emit_targets_in_commands {
                 j.push_static(b" (");
                 line_offset.advance(b" (");
@@ -695,16 +698,8 @@ pub fn post_process_js_chunk(
                 line_offset.advance(b")");
             }
 
-            match comment_type {
-                CommentType::Multiline => {
-                    j.push_static(b" */\n");
-                    line_offset.advance(b" */\n");
-                }
-                CommentType::Single => {
-                    j.push_static(b"\n");
-                    line_offset.advance(b"\n");
-                }
-            }
+            j.push_static(b"\n");
+            line_offset.advance(b"\n");
         }
 
         if is_runtime {
```