# Out-of-bounds read parsing Lock-Token

## Classification

Memory safety, medium severity. Confidence: certain.

## Affected Locations

`modules/dav/main/mod_dav.c:3395`

## Summary

`dav_method_unlock()` parses the `Lock-Token` request header by advancing past a leading `<` and then checking the last byte of the remaining string. For a header value exactly `<`, the remaining string is empty, so `strlen(locktoken_txt) - 1` underflows and indexes before the buffer.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- A WebDAV locks provider is enabled, so `DAV_GET_HOOKS_LOCKS(r)` is non-NULL.
- A client sends an `UNLOCK` request with `Lock-Token: <`.

## Proof

The vulnerable path is reached before resource validation:

```c
locktoken_txt = apr_pstrdup(r->pool, const_locktoken_txt);
if (locktoken_txt[0] != '<') {
    return HTTP_BAD_REQUEST;
}
locktoken_txt++;

if (locktoken_txt[strlen(locktoken_txt) - 1] != '>') {
    return HTTP_BAD_REQUEST;
}
```

For `Lock-Token: <`:

- `apr_pstrdup()` copies the header as `"<\0"`.
- `locktoken_txt[0] == '<'` passes.
- `locktoken_txt++` points at the terminating NUL.
- `strlen(locktoken_txt)` is `0`.
- `strlen(locktoken_txt) - 1` underflows as `size_t`.
- `locktoken_txt[...]` forms an invalid index and reads before the intended string.

Runtime confirmation from the reproducer showed the equivalent expression aborting under UBSan with an unsigned offset overflow diagnostic.

## Why This Is A Real Bug

The code performs pointer arithmetic and indexing outside the bounds of the copied header string for attacker-controlled input. Even if common non-sanitized builds often read the original `<` byte and return `400 Bad Request`, the C behavior is undefined. Sanitized or hardened builds can abort, making the issue malformed-request-triggerable in the UNLOCK header parser.

## Fix Requirement

Reject an empty token body before subtracting one from `strlen(locktoken_txt)`, or validate the original header length before advancing past `<`.

## Patch Rationale

The patch adds an explicit empty-string check before evaluating the final-character expression. Because C short-circuits `||`, `strlen(locktoken_txt) - 1` is only evaluated when `locktoken_txt[0] != '\0'`, preventing underflow while preserving the existing malformed-header response behavior.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/dav/main/mod_dav.c b/modules/dav/main/mod_dav.c
index 2625f90..b43067e 100644
--- a/modules/dav/main/mod_dav.c
+++ b/modules/dav/main/mod_dav.c
@@ -3392,7 +3392,8 @@ static int dav_method_unlock(request_rec *r)
     }
     locktoken_txt++;
 
-    if (locktoken_txt[strlen(locktoken_txt) - 1] != '>') {
+    if (locktoken_txt[0] == '\0'
+        || locktoken_txt[strlen(locktoken_txt) - 1] != '>') {
         /* ### should provide more specifics... */
         return HTTP_BAD_REQUEST;
     }
```