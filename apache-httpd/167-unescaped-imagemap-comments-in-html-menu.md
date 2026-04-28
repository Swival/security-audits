# Unescaped Imagemap Comments in HTML Menu

## Classification

Medium severity vulnerability: stored/scriptable HTML injection in generated imagemap menu responses.

Confidence: certain.

## Affected Locations

`modules/mappers/mod_imagemap.c:502`

## Summary

Imagemap map-file comments are emitted into semiformatted and unformatted HTML menu responses without HTML escaping. A comment line beginning with `#` has only the leading `#` removed before being passed to `menu_comment()`, which writes the remaining text directly with `ap_rvputs()`. If an attacker can influence map-file comments, they can inject scriptable HTML into a `text/html` response served from the site origin.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched from the provided source and reproducer evidence.

## Preconditions

- `ImapMenu semiformatted` or `ImapMenu unformatted` is enabled.
- The map file contains attacker-controlled comment HTML.
- The request causes menu rendering, such as missing, invalid, or zero coordinates that set `showmenu`.

## Proof

`imap_handler_internal()` reads map-file lines into `input`. For comment lines:

```c
if (input[0] == '#') {
    if (showmenu) {
        menu_comment(r, imap_menu, input + 1);
    }
    continue;
}
```

This strips only the leading `#` and passes the rest of the line to `menu_comment()`.

Before the patch, semiformatted and unformatted comments were written raw:

```c
ap_rvputs(r, comment, "\n", NULL);
```

A practical trigger is:

```apache
ImapMenu semiformatted
```

Map file:

```text
#<script>alert(document.domain)</script>
rect /safe.html 0,0 10,10 "safe"
```

Requesting the map without valid coordinates, for example:

```text
GET /example.map
```

sets `showmenu`, emits a `text/html` menu response, reads the comment, strips `#`, and writes `<script>alert(document.domain)</script>` directly into the response body.

## Why This Is A Real Bug

The generated menu response is explicitly HTML:

```c
ap_set_content_type_ex(r, "text/html; charset=ISO-8859-1", 1);
```

Other map-derived menu values are already escaped before being emitted:

```c
etext = ap_escape_html(r->pool, text);
```

in `menu_default()` and `menu_directive()`. Comments were the inconsistent exception. Because attacker-controlled comment text can be persisted in the map file and served as raw HTML in the site origin, this is a real stored HTML/script injection issue, not only malformed output.

## Fix Requirement

Escape comment text with `ap_escape_html()` before writing it into semiformatted or unformatted menu HTML.

## Patch Rationale

The patch preserves existing menu behavior while changing only the output encoding of comment content. `ap_escape_html(r->pool, comment)` converts HTML-significant characters such as `<`, `>`, `&`, and quotes into safe entities before `ap_rvputs()` writes the value into the response.

Formatted menus remain unchanged because comments are ignored there except for a newline.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/mappers/mod_imagemap.c b/modules/mappers/mod_imagemap.c
index 66d10bb..e27ad36 100644
--- a/modules/mappers/mod_imagemap.c
+++ b/modules/mappers/mod_imagemap.c
@@ -508,10 +508,10 @@ static void menu_comment(request_rec *r, char *menu, char *comment)
         ap_rputs("\n", r);         /* print just a newline if 'formatted' */
     }
     else if (!strcasecmp(menu, "semiformatted") && *comment) {
-        ap_rvputs(r, comment, "\n", NULL);
+        ap_rvputs(r, ap_escape_html(r->pool, comment), "\n", NULL);
     }
     else if (!strcasecmp(menu, "unformatted") && *comment) {
-        ap_rvputs(r, comment, "\n", NULL);
+        ap_rvputs(r, ap_escape_html(r->pool, comment), "\n", NULL);
     }
 }
```