# Unescaped Variant List Fields In Error HTML

## Classification

Medium severity vulnerability: stored HTML/script injection through type-map
metadata that surfaces in generated `text/html` error responses.

## Affected Locations

`modules/mappers/mod_negotiation.c:2650`
`modules/mappers/mod_negotiation.c:2654`
`modules/mappers/mod_negotiation.c:2658`
`modules/mappers/mod_negotiation.c:2663`
`modules/mappers/mod_negotiation.c:2667`

## Summary

`make_variant_list()` builds the HTML stored under `r->notes["variant-list"]`
by concatenating per-variant fields without HTML-escaping. The
`description`, `mime_type`, the joined languages list, `content_charset`,
and `content_encoding` are all inserted between the literal `<li><a>` markup
without escaping. When a type-map publishes attacker-controlled values for
these fields, a 406 error response includes the unescaped data inside the
canned `text/html` error body produced by `add_optional_notes()` and
`ap_send_error_response()`.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

A type-map served by `mod_negotiation` contains untrusted HTML-special
characters in any of `Description:`, `Content-Type:`, `Content-Language:`,
`Content-Charset:`, or `Content-Encoding:` fields, and a request
makes the variants unacceptable, triggering the 406 default error body.

## Proof

A reproduced path through `mod_negotiation` is:

```text
URI: safe.html
Content-Type: text/html
Description: <script>alert`1`</script>
```

`modules/mappers/mod_negotiation.c:1013` parses the type-map `Description:`
field, line `1021` stores it as `mime_info.description`, line `2650`
inserts it into the variant list with no escaping, and line `2679` stores
the result in `r->notes["variant-list"]`.

A request that makes the variant unacceptable, such as
`Accept: image/png`, reaches `do_negotiation()`, returns
`HTTP_NOT_ACCEPTABLE`, and the default 406 body propagates the unescaped
description through `get_canned_error_string()` and
`ap_send_error_response()`.

## Why This Is A Real Bug

The body is generated as HTML by `ap_send_error_response()` using
`text/html`. The `description`, `mime_type`, `content_charset`,
`content_encoding`, and joined language list are all attacker-influenced
text from the type-map source and must therefore be HTML-escaped before
being concatenated into a `<li>...</li>` HTML fragment.

The variant-list stored note is constructed as HTML with intentional
markup (`<li><a href="...">...</a>`), so the fix must escape the
attacker-controlled fields at the point where they are emitted into the
fragment, rather than escaping the whole stored note in
`add_optional_notes()`. Escaping the entire note would mangle the
intentional markup and would also double-escape the existing
`ap_escape_html()` already applied to `error-notes` at logging time.

## Fix Requirement

HTML-escape `description`, `mime_type`, the joined languages list,
`content_charset`, and `content_encoding` in `make_variant_list()` before
they are pushed into the variant-list HTML.

## Patch Rationale

Each attacker-influenced field is wrapped in `ap_escape_html(r->pool, ...)`
at its single emission site in `make_variant_list()`. The intentional
markup (`<li><a href="...">`, `</a>`, `</li>`) remains untouched, and
fields that already had special handling (the `filename` href and link
text) keep their existing escaping. Stored `error-notes` values built
elsewhere are unaffected, preserving the pre-formatted content many
producers already supply (including the values that
`server/log.c` already passes through `ap_escape_html`).

## Residual Risk

None.

## Patch

```diff
diff --git a/modules/mappers/mod_negotiation.c b/modules/mappers/mod_negotiation.c
index 1234567..89abcde 100644
--- a/modules/mappers/mod_negotiation.c
+++ b/modules/mappers/mod_negotiation.c
@@ -2633,9 +2633,9 @@ static char *make_variant_list(request_rec *r, negotiation_state *neg)
         var_rec *variant = &((var_rec *) neg->avail_vars->elts)[i];
         const char *filename = variant->file_name ? variant->file_name : "";
         apr_array_header_t *languages = variant->content_languages;
-        const char *description = variant->description
-                                    ? variant->description
-                                    : "";
+        const char *description = variant->description
+                                    ? ap_escape_html(r->pool, variant->description)
+                                    : "";

         /* The format isn't very neat, and it would be nice to make
          * the tags human readable (eg replace 'language en' with 'English').
@@ -2651,15 +2651,18 @@ static char *make_variant_list(request_rec *r, negotiation_state *neg)

         if (variant->mime_type && *variant->mime_type) {
             *((const char **) apr_array_push(arr)) = ", type ";
-            *((const char **) apr_array_push(arr)) = variant->mime_type;
+            *((const char **) apr_array_push(arr)) =
+                ap_escape_html(r->pool, variant->mime_type);
         }
         if (languages && languages->nelts) {
             *((const char **) apr_array_push(arr)) = ", language ";
-            *((const char **) apr_array_push(arr)) = apr_array_pstrcat(r->pool,
-                                                       languages, ',');
+            *((const char **) apr_array_push(arr)) =
+                ap_escape_html(r->pool,
+                               apr_array_pstrcat(r->pool, languages, ','));
         }
         if (variant->content_charset && *variant->content_charset) {
             *((const char **) apr_array_push(arr)) = ", charset ";
-            *((const char **) apr_array_push(arr)) = variant->content_charset;
+            *((const char **) apr_array_push(arr)) =
+                ap_escape_html(r->pool, variant->content_charset);
         }
         if (variant->content_encoding) {
             *((const char **) apr_array_push(arr)) = ", encoding ";
-            *((const char **) apr_array_push(arr)) = variant->content_encoding;
+            *((const char **) apr_array_push(arr)) =
+                ap_escape_html(r->pool, variant->content_encoding);
         }
         *((const char **) apr_array_push(arr)) = "</li>\n";
```
