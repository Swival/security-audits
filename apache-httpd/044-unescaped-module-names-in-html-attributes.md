# Unescaped Module Names In Server-Info HTML

## Classification

Medium severity vulnerability: HTML injection / cross-site scripting in generated `server-info` output.

## Affected Locations

`modules/generators/mod_info.c:670`

Additional affected output sites in the provided source:

- `modules/generators/mod_info.c:817`
- `modules/generators/mod_info.c:853`
- `modules/generators/mod_info.c:958`

## Summary

`mod_info` prints loaded module names directly into HTML attribute values and text nodes in the `server-info` response. If a loaded module name contains HTML metacharacters such as `"`, `<`, or `>`, the generated page can contain attacker-controlled markup or script.

The patch escapes module names with `ap_escape_html()` before inserting them into `href`, `name`, and text contexts.

## Provenance

Verified and reproduced from Swival Security Scanner findings: https://swival.dev

Confidence: certain.

## Preconditions

- `mod_info` is enabled and reachable through a `server-info` handler.
- A loaded module has a `module.name` value containing HTML attribute or text metacharacters.
- A user with access to `server-info` views the generated page.

## Proof

Module names are collected from loaded module structures through `get_sorted_modules()` and emitted by `display_info()`.

Before the patch, `modp->name` was printed raw into:

```c
ap_rprintf(r, "<a href=\"#%s\">%s</a>", modp->name, modp->name);
```

and:

```c
ap_rprintf(r,
           "<dl><dt><a name=\"%s\"><strong>Module Name:</strong></a> "
           "<font size=\"+1\"><tt><a href=\"?%s\">%s</a></tt></font></dt>\n",
           modp->name, modp->name, modp->name);
```

and the `?list` body output:

```c
ap_rputs(modp->name, r);
```

A module name such as:

```text
x" autofocus onfocus=alert(1) y=".c
```

can produce attribute-breaking HTML similar to:

```html
<a href="#x" autofocus onfocus=alert(1) y=".c">x" autofocus onfocus=alert(1) y=".c</a>
```

This is reachable through `GET` requests handled by `server-info`.

## Why This Is A Real Bug

`server/config.c` only strips path separators from module names before modules are added to `ap_top_module`; it does not reject or encode HTML metacharacters. `display_info()` later treats those names as safe HTML.

Because the same untrusted value is inserted into quoted attributes and text nodes without encoding, a crafted loaded module name can alter the structure of the generated HTML and inject executable markup into the administrative `server-info` page.

The required precondition is privileged and configuration-dependent, but under that precondition the behavior is reachable and exploitable.

## Fix Requirement

All module names must be HTML-escaped before being written to the `server-info` response in either attribute values or text nodes.

## Patch Rationale

The patch applies `ap_escape_html(r->pool, modp->name)` at every confirmed `display_info()` output site where `modp->name` is rendered into HTML:

- Loaded module anchor `href` attribute and link text.
- Per-module anchor `name` attribute, query link `href`, and link text.
- `?list` module-name body text.

This preserves the displayed module name while ensuring metacharacters are encoded before reaching the browser.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/generators/mod_info.c b/modules/generators/mod_info.c
index a94e4e4..f24d2b1 100644
--- a/modules/generators/mod_info.c
+++ b/modules/generators/mod_info.c
@@ -817,8 +817,9 @@ static int display_info(request_rec * r)
             modules = get_sorted_modules(r->pool);
             for (i = 0; i < modules->nelts; i++) {
                 modp = APR_ARRAY_IDX(modules, i, module *);
-                ap_rprintf(r, "<a href=\"#%s\">%s</a>", modp->name,
-                           modp->name);
+                ap_rprintf(r, "<a href=\"#%s\">%s</a>",
+                           ap_escape_html(r->pool, modp->name),
+                           ap_escape_html(r->pool, modp->name));
                 if (i < modules->nelts) {
                     ap_rputs(", ", r);
                 }
@@ -853,7 +854,9 @@ static int display_info(request_rec * r)
                     ap_rprintf(r,
                                "<dl><dt><a name=\"%s\"><strong>Module Name:</strong></a> "
                                "<font size=\"+1\"><tt><a href=\"?%s\">%s</a></tt></font></dt>\n",
-                               modp->name, modp->name, modp->name);
+                               ap_escape_html(r->pool, modp->name),
+                               ap_escape_html(r->pool, modp->name),
+                               ap_escape_html(r->pool, modp->name));
                     ap_rputs("<dt><strong>Content handlers:</strong> ", r);
 
                     if (module_find_hook(modp, ap_hook_get_handler)) {
@@ -958,7 +961,7 @@ static int display_info(request_rec * r)
         for (i = 0; i < modules->nelts; i++) {
             modp = APR_ARRAY_IDX(modules, i, module *);
             ap_rputs("<dd>", r);
-            ap_rputs(modp->name, r);
+            ap_rputs(ap_escape_html(r->pool, modp->name), r);
             ap_rputs("</dd>", r);
         }
         ap_rputs("</dl><hr />", r);
```