# edit* zero-length match recursion

## Classification

Logic error, medium severity. Confidence: certain.

## Affected Locations

`modules/metadata/mod_headers.c:648`

## Summary

`Header edit*` recursively applies a configured regular expression to all matches in a header value. If the regex can match an empty string, the recursive step may receive the same input pointer repeatedly, causing unbounded recursion, stack exhaustion, and request or worker failure.

## Provenance

Verified from the supplied source, reproducer, and patch. Initially reported by Swival Security Scanner: https://swival.dev

## Preconditions

- `Header edit*` or equivalent `hdr_edit_r` handling is configured.
- The configured regex can match an empty string.
- A matching request or response header reaches `process_regexp()`.

## Proof

A concrete trigger is:

```apache
Header edit* X "^" "prefix"
```

For any response containing header `X`, regex `^` matches at offset 0 with `pmatch[0].rm_so == 0` and `pmatch[0].rm_eo == 0`.

Execution path:

- `header_inout_cmd()` accepts `edit*` and stores `hdr_edit_r`.
- `do_headers_fixup()` handles `hdr_edit_r` for matching headers.
- `edit_header()` calls `process_regexp()`.
- `process_regexp()` recurses with `value + pmatch[0].rm_eo`.
- For a zero-length match, `pmatch[0].rm_eo == 0`, so recursion receives the same `value` pointer indefinitely.

## Why This Is A Real Bug

The recursive `edit*` implementation assumes every successful match consumes input. Empty-string regex matches violate that assumption. Because the recursive call is made with an unchanged pointer, there is no progress condition, so the same match is found repeatedly until stack exhaustion and/or request-pool allocation growth terminates processing.

## Fix Requirement

`edit*` processing must not recurse on an unchanged input position. Zero-length matches must either be rejected or handled without re-entering `process_regexp()` on the same pointer.

## Patch Rationale

The patch detects `pmatch[0].rm_eo == pmatch[0].rm_so` in the `hdr_edit_r` path and stops recursive processing for that match by setting `remainder` directly to `value + pmatch[0].rm_eo`.

This preserves single substitution behavior for the current match while preventing the recursive call from receiving the same input pointer. Non-empty matches retain the existing recursive behavior.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/metadata/mod_headers.c b/modules/metadata/mod_headers.c
index f514b4b..085eefc 100644
--- a/modules/metadata/mod_headers.c
+++ b/modules/metadata/mod_headers.c
@@ -649,10 +649,15 @@ static const char *process_regexp(header_entry *hdr, const char *value,
         remainder = value + pmatch[0].rm_eo;
     }
     else { /* recurse to edit multiple matches if applicable */
-        remainder = process_regexp(hdr, value + pmatch[0].rm_eo, r);
-        if (remainder == NULL)
-            return NULL;
-        diffsz += strlen(remainder) - strlen(value + pmatch[0].rm_eo);
+        if (pmatch[0].rm_eo == pmatch[0].rm_so) {
+            remainder = value + pmatch[0].rm_eo;
+        }
+        else {
+            remainder = process_regexp(hdr, value + pmatch[0].rm_eo, r);
+            if (remainder == NULL)
+                return NULL;
+            diffsz += strlen(remainder) - strlen(value + pmatch[0].rm_eo);
+        }
     }
     ret = apr_palloc(r->pool, strlen(value) + 1 + diffsz);
     memcpy(ret, value, pmatch[0].rm_so);
```