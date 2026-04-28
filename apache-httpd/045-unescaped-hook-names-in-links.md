# Unescaped Hook Names in Links

## Classification

Vulnerability: HTML injection / cross-site scripting risk.

Severity: Medium.

Confidence: Certain.

## Affected Locations

`modules/generators/mod_info.c:547`

`modules/generators/mod_info.c:653`

## Summary

`mod_info` renders hook registration names into `/server-info` HTML without escaping. A loaded module can register a hook name containing HTML metacharacters, and `dump_a_hook()` inserts that name directly into both an anchor `href` attribute and visible link text.

This allows HTML injection in `GET /server-info?hooks` and in the full `GET /server-info` page where active hooks are included.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and confirmed from source-level data flow through hook registration, hook enumeration, and HTML emission.

## Preconditions

A loaded module registers a hook name containing HTML metacharacters.

Example module name:

```text
x"></a><script>alert(1)</script><a href="
```

## Proof

Hook names originate from hook registration state returned by `hook_get()` and are consumed in `dump_a_hook()`.

`dump_a_hook()` obtains hook entries:

```c
apr_array_header_t *hooks = hook_get();
elts = (hook_struct_t *) hooks->elts;
```

It then emits `elts[i].szName` directly into HTML:

```c
ap_rprintf(r,
           "&nbsp;&nbsp; %02d <a href=\"%c%s\">%s</a> <br/>",
           elts[i].nOrder, qs, elts[i].szName, elts[i].szName);
```

A malicious hook name such as:

```text
x"></a><script>alert(1)</script><a href="
```

can render as:

```html
<a href="?x"></a><script>alert(1)</script><a href="">...
```

The vulnerable path is reachable via:

```text
GET /server-info?hooks
```

and also via the full:

```text
GET /server-info
```

because `display_info()` calls `show_active_hooks()`, which calls `dump_a_hook()`.

## Why This Is A Real Bug

`mod_info` is explicitly generating an HTML response with `text/html`. Data copied into an HTML attribute or text node must be encoded for that context.

The affected value is not guaranteed safe:

- Hook names are sourced from hook registration data.
- Dynamic module loading can reach hook registration.
- Module name sanitization only strips path separators and does not reject HTML metacharacters.
- The same untrusted string is placed in both an attribute and body text.
- No `ap_escape_html()` or equivalent escaping was applied before output.

Therefore a module-controlled hook name can break out of the intended anchor markup and inject arbitrary HTML/script into the server-info page.

## Fix Requirement

Escape hook names before emitting them into HTML.

The visible link text must be HTML-escaped, and the `href` value must not receive raw metacharacters capable of breaking the quoted attribute.

## Patch Rationale

The patch applies `ap_escape_html(r->pool, elts[i].szName)` to both uses of the hook name in `dump_a_hook()`.

This prevents characters such as `<`, `>`, `"`, and `&` from being interpreted as markup or attribute delimiters in the generated HTML. The generated link remains functional for normal hook names while preventing injected markup from becoming executable page content.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/generators/mod_info.c b/modules/generators/mod_info.c
index a94e4e4..c29c635 100644
--- a/modules/generators/mod_info.c
+++ b/modules/generators/mod_info.c
@@ -653,7 +653,9 @@ static int dump_a_hook(request_rec * r, hook_get_t hook_get)
     for (i = 0; i < hooks->nelts; i++) {
         ap_rprintf(r,
                    "&nbsp;&nbsp; %02d <a href=\"%c%s\">%s</a> <br/>",
-                   elts[i].nOrder, qs, elts[i].szName, elts[i].szName);
+                   elts[i].nOrder, qs,
+                   ap_escape_html(r->pool, elts[i].szName),
+                   ap_escape_html(r->pool, elts[i].szName));
     }
     return 0;
 }
```