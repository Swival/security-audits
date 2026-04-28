# Unescaped Alt Text In Image Alt

## Classification

Medium-severity vulnerability: HTML attribute injection / XSS in generated directory indexes.

Confidence: certain.

## Affected Locations

`modules/generators/mod_autoindex.c:1605`

Raw sinks reproduced at:

`modules/generators/mod_autoindex.c:1716`

`modules/generators/mod_autoindex.c:1806`

## Summary

Configured `AddAlt` text and parenthesized `AddIcon` alt text are stored and later copied into autoindex entries. When `mod_autoindex` renders icon images for FancyIndexing or TableIndexing, it emits `ar[x]->alt` directly inside an `<img alt="[...]">` attribute without HTML escaping. Quote-bearing alt text can break out of the attribute and inject attacker-controlled HTML attributes or script-bearing markup.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced from source review and patched in `086-unescaped-alt-text-in-image-alt.patch`.

## Preconditions

- Attacker can configure `AddAlt` or parenthesized `AddIcon` alt text for an indexed directory.
- Directory is served with `Options Indexes`.
- Autoindex output uses `FancyIndexing` or `HTMLTable`.
- Icons are not suppressed.

## Proof

`AddAlt` and parenthesized `AddIcon` values enter `add_alt` / `add_icon` and are stored by `push_item`.

During directory indexing, matching configured alt values are copied into `p->alt` through `find_alt` / `find_default_alt` in `make_autoindex_entry`.

The vulnerable emission occurs in `output_directories`, where both table and fancy output write `ar[x]->alt` directly inside:

```html
<img ... alt="[USER_CONTROLLED_ALT]">
```

The adjacent icon URL is already escaped with `ap_escape_html`, but the alt text was not.

A concrete trigger is:

```apache
Options Indexes
IndexOptions FancyIndexing
AddIcon "(x\" onerror=\"alert(1),/icons/text.gif)" *.txt
```

A matching `*.txt` entry causes the generated autoindex page to include quote-bearing attacker-controlled content inside the `alt` attribute, enabling attribute injection and XSS.

## Why This Is A Real Bug

The data flow is direct and security-sensitive:

- Source: administrator-controlled but attacker-reachable `AddAlt` / `AddIcon` alt text.
- Storage: `push_item` preserves the configured string.
- Propagation: `find_alt` / `find_default_alt` copy it into `ar[x]->alt`.
- Sink: `output_directories` emits it into an HTML attribute without escaping.

HTML attribute context requires escaping at least quotes, `<`, `>`, and `&`. Without `ap_escape_html`, a value containing `"` exits the `alt` attribute and injects new attributes such as event handlers.

## Fix Requirement

HTML-escape `ar[x]->alt` before emitting it inside image `alt` attributes in all autoindex rendering paths.

## Patch Rationale

The patch applies `ap_escape_html(scratch, ...)` to the alt-text expression in both affected `<img alt>` emitters:

- TableIndexing icon output.
- FancyIndexing icon output.

This matches the existing treatment of the adjacent icon URL and preserves the existing fallback value of `"   "` when no alt text is configured.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/generators/mod_autoindex.c b/modules/generators/mod_autoindex.c
index 715b49c..9eb1e8a 100644
--- a/modules/generators/mod_autoindex.c
+++ b/modules/generators/mod_autoindex.c
@@ -1713,7 +1713,9 @@ static void output_directories(struct ent **ar, int n,
                               ap_escape_html(scratch,
                                              ar[x]->icon ? ar[x]->icon
                                                          : d->default_icon),
-                              "\" alt=\"[", (ar[x]->alt ? ar[x]->alt : "   "),
+                              "\" alt=\"[", ap_escape_html(scratch,
+                                                     ar[x]->alt ? ar[x]->alt
+                                                                : "   "),
                               "]\"", NULL);
                     if (d->icon_width) {
                         ap_rprintf(r, " width=\"%d\"", d->icon_width);
@@ -1803,7 +1805,9 @@ static void output_directories(struct ent **ar, int n,
                               ap_escape_html(scratch,
                                              ar[x]->icon ? ar[x]->icon
                                                          : d->default_icon),
-                              "\" alt=\"[", (ar[x]->alt ? ar[x]->alt : "   "),
+                              "\" alt=\"[", ap_escape_html(scratch,
+                                                     ar[x]->alt ? ar[x]->alt
+                                                                : "   "),
                               "]\"", NULL);
                     if (d->icon_width) {
                         ap_rprintf(r, " width=\"%d\"", d->icon_width);
```