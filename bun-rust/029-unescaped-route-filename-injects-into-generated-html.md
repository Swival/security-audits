# Unescaped Route Filename Injects Into Generated HTML

## Classification

Injection, medium severity.

## Affected Locations

`src/runtime/bake/DevServer.rs:2763`

## Summary

`generate_html_payload` derived a script URL display name from the served HTML route filename and inserted it directly into a quoted HTML `src` attribute. ASCII filenames were accepted unchanged, so a filename containing `"` could terminate the attribute and inject attacker-controlled HTML/JS into the dev page.

## Provenance

Verified from the supplied source, reproducer, and patch. Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

A lower-privileged local user can create or rename an HTML route file served by the dev server.

## Proof

`generate_html_payload` takes the basename of `html_ref.bundle.path`, removes `.html`, and stores it in `display_name`.

Before the patch, only non-ASCII names were replaced:

```rust
if !strings::is_all_ascii(display_name) {
    display_name = b"page";
}
```

The resulting bytes were appended inside a quoted `src` attribute:

```rust
array.extend_from_slice(b"<script type=\"module\" crossorigin src=\"");
array.extend_from_slice(CLIENT_PREFIX.as_bytes());
array.extend_from_slice(b"/");
array.extend_from_slice(display_name);
array.extend_from_slice(b"-");
```

A POSIX filename such as:

```text
x" onerror="alert(1)" x=".html
```

therefore generated a script tag equivalent to:

```html
<script type="module" crossorigin src="/_bun/client/x" onerror="alert(1)" x="-<hex>.js" data-bun-dev-server-script></script>
```

This breaks out of the `src` attribute and allows browser-side JavaScript execution in the dev server origin.

## Why This Is A Real Bug

The input is attacker-controlled under the stated local file-control precondition, is preserved when ASCII, and reaches HTML attribute context without escaping or URL encoding. The injected quote changes the browser’s parsed DOM, so this is not merely a malformed URL; it creates attacker-controlled attributes in generated HTML served by `on_html_request_with_bundle`.

## Fix Requirement

The filename-derived value must be safe for insertion into a quoted HTML attribute. At minimum, dangerous attribute delimiters must not be emitted unescaped. Percent-encoding or HTML-attribute escaping would also satisfy this requirement.

## Patch Rationale

The patch rejects ASCII double quotes in `display_name` and falls back to the constant safe name `page`:

```rust
if !strings::is_all_ascii(display_name) || display_name.contains(&b'"') {
    display_name = b"page";
}
```

This removes the demonstrated attribute-breakout primitive because `"` can no longer appear in the generated quoted `src` attribute from the route basename.

## Residual Risk

None

## Patch

```diff
diff --git a/src/runtime/bake/DevServer.rs b/src/runtime/bake/DevServer.rs
index 6c47400fe0..58d0a69298 100644
--- a/src/runtime/bake/DevServer.rs
+++ b/src/runtime/bake/DevServer.rs
@@ -2765,8 +2765,7 @@ impl DevServer {
             paths::basename(unsafe { &(&(*html.html_bundle).bundle).path }),
             b".html",
         );
-        // TODO: function for URL safe chars
-        if !strings::is_all_ascii(display_name) {
+        if !strings::is_all_ascii(display_name) || display_name.contains(&b'"') {
             display_name = b"page";
         }
```