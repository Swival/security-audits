# Unescaped Alt Text In Row Class

## Classification

Vulnerability, medium severity.

Confidence: certain.

## Affected Locations

`modules/generators/mod_autoindex.c:1586`

`modules/generators/mod_autoindex.c:1695`

`modules/generators/mod_autoindex.c:1697`

## Summary

`mod_autoindex` can emit configured `AddAlt` text directly inside an HTML `class` attribute when `IndexOptions AddAltClass`, table indexing, and an `IndexStyleSheet` are active. A quote in the configured alt text breaks out of the `class` attribute and allows attacker-controlled HTML attributes to be injected into generated directory index rows.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched from source-level evidence in `modules/generators/mod_autoindex.c`.

## Preconditions

- Directory indexing is enabled.
- Table-style autoindex output is active.
- `IndexStyleSheet` is configured, causing styled table row classes to be emitted.
- `IndexOptions AddAltClass` is enabled.
- A matching `AddAlt`, `AddAltByType`, or `AddAltByEncoding` value contains attacker-controlled attribute-breaking characters such as `"`.
- The attacker can influence applicable per-directory autoindex configuration, for example through writable `.htaccess` where `AllowOverride Indexes` permits these directives.

## Proof

`AddAlt` stores the configured alt text through `push_item`, where `p->data` is set from the directive value.

`make_autoindex_entry` resolves matching alt text and assigns it to `p->alt`.

In `output_directories`, styled table rows with `AddAltClass` enabled build a row class from `ar[x]->alt`:

```c
char *altclass = apr_pstrdup(scratch, ar[x]->alt);
ap_str_tolower(altclass);
ap_rvputs(r, "   <tr class=\"", ( x & 0x1) ? "odd-" : "even-", altclass, "\">", NULL);
```

Because `altclass` is emitted inside a quoted HTML attribute without escaping, an alt value containing a quote can inject additional attributes. For example, a configured alt text equivalent to:

```text
x" onclick="alert(1)
```

can produce a row similar to:

```html
<tr class="even-x" onclick="alert(1)">
```

This affects each generated table index row whose entry matches the configured alt text while the required options are active.

## Why This Is A Real Bug

The value crosses a trust boundary from configuration-controlled `AddAlt` data into generated HTML attribute context without escaping. HTML attribute syntax treats quotes as delimiters, so the emitted value can terminate `class` and append attacker-controlled attributes. This is stored/config-driven HTML injection with XSS impact where an attacker can control relevant autoindex configuration.

Spaces alone do not break out of the quoted attribute, but quote-based attribute injection is directly supported by the source.

## Fix Requirement

Escape the alt-derived class fragment before emitting it into the HTML attribute, or restrict generated class names to a safe character set before output.

## Patch Rationale

The patch applies `ap_escape_html` to the lowercased `altclass` immediately before writing it into the `<tr class="...">` attribute. This preserves the existing `AddAltClass` behavior for normal class text while encoding attribute-breaking characters such as `"` so they cannot terminate the class attribute.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/generators/mod_autoindex.c b/modules/generators/mod_autoindex.c
index 715b49c..bd8d875 100644
--- a/modules/generators/mod_autoindex.c
+++ b/modules/generators/mod_autoindex.c
@@ -1694,7 +1694,7 @@ static void output_directories(struct ent **ar, int n,
                     /* Include alt text in class name, distinguish between odd and even rows */
                     char *altclass = apr_pstrdup(scratch, ar[x]->alt);
                     ap_str_tolower(altclass);
-                    ap_rvputs(r, "   <tr class=\"", ( x & 0x1) ? "odd-" : "even-", altclass, "\">", NULL);
+                    ap_rvputs(r, "   <tr class=\"", ( x & 0x1) ? "odd-" : "even-", ap_escape_html(scratch, altclass), "\">", NULL);
                 } else {
                     /* Distinguish between odd and even rows */
                     ap_rvputs(r, "   <tr class=\"", ( x & 0x1) ? "odd" : "even", "\">", NULL);
```