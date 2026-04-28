# Out-of-Bounds Read in META Header Scan

## Classification

Memory safety: out-of-bounds read; severity high; confidence certain

## Affected Locations

`modules/filters/mod_proxy_html.c:677`

## Summary

`metafix()` scans bounded APR bucket data for `<meta http-equiv ...>` when `ProxyHTMLMeta` is enabled. After matching `http-equiv`, it advances with `while (!apr_isalpha(*++p));` without checking the regex match end or bucket length. A malformed tag such as `<meta http-equiv=>` at the end of a bucket causes a read past `buf + len`.

## Provenance

Verified and reproduced from the supplied finding and reproducer evidence.

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- `ProxyHTMLMeta` is enabled.
- A proxied HTML response contains a malformed META `http-equiv` directive.
- The malformed META tag is present in a bounded APR bucket, which is not guaranteed to be NUL-terminated.

## Proof

`proxy_html_filter()` passes APR bucket bytes to `metafix(buf, len)` when `cfg->metafix` is set.

Inside `metafix()`:

- `seek_meta` can match `<meta ... http-equiv ...>` within the bounded buffer.
- `p = buf + offs + pmatch[1].rm_eo` points just after the matched `http-equiv`.
- `while (!apr_isalpha(*++p));` advances and dereferences without checking `pmatch[0].rm_eo` or `len`.
- For input `xxxx<meta http-equiv=>`, the loop reads `>` and then dereferences one byte past `buf + len` when the tag ends the bucket.
- An ASan harness mirroring the committed pointer logic reports a heap-buffer-overflow read at the `*++p` dereference.

## Why This Is A Real Bug

APR bucket data is length-delimited and not guaranteed to contain a trailing NUL byte. The scan treats the buffer as if a later alphabetic byte must exist, but malformed input can place no alphabetic byte before the end of the matched META tag or the bucket. This makes the out-of-bounds read reachable during normal proxy-html output filtering and can crash under guard/ASan conditions or consume adjacent memory as part of the header scan.

## Practical Exploit Scenario

A reverse proxy serves customer-facing HTML by fronting an internal application server, configured with the URL-rewriting filter chain that normalizes META tags during transit:

```apache
<Location /up>
    ProxyPass        http://app.internal/
    ProxyPassReverse http://app.internal/
    ProxyHTMLEnable  On
    ProxyHTMLMeta    On
</Location>
```

`ProxyHTMLMeta` is enabled because the operator uses `mod_proxy_html` to merge `Content-Type` charset hints from `<meta http-equiv>` into the response. The application backend is *not* fully trusted: it is operated by a different team, contains attacker-influenced content (user comments, document previews, tenant-uploaded HTML, a CMS with template injection), or has simply been compromised.

An attacker arranges for a single response from the backend to contain a malformed META tag at the right offset:

```html
xxxx<meta http-equiv=>
```

The `seek_meta` regex matches the directive within the bounded APR bucket. `metafix` advances `p` past `http-equiv` and enters `while (!apr_isalpha(*++p))`, sailing through `=` and `>` looking for an alphabetic header token. Because the malformed tag has none, the loop walks straight off the end of the bucket buffer. The next byte read might be allocator metadata, a guard page, or an unrelated bucket; under hardened builds (ASan, FORTIFY, guard pages) the worker faults and exits. Even without hardening, the read can return adjacent bytes that the loop's `apr_isalpha` accepts, leading metafix to copy memory beyond the bucket into the response's `header` and `content` notes, where downstream filters then echo or log them.

An attacker who controls only a small fragment of backend HTML can crash the proxy on every render of the affected page. Public-facing CDN cache miss patterns turn this into broad service degradation: every cold request that hits a regenerated page kills a worker, and the cache layer dutifully retries through new workers until none remain. The bug is reachable by any input that influences proxied HTML, which is typical of mod_proxy_html deployments precisely because they exist to clean up other people's HTML.

## Fix Requirement

Bound all `p` and `q` scans in `metafix()` to the current META regex match end, `buf + offs + pmatch[0].rm_eo`, before every dereference. If no valid header token is found within the match, skip the malformed directive.

## Patch Rationale

The patch introduces `match_end` and constrains the header and content scans to it:

- Header discovery now uses `while (++p < match_end && !apr_isalpha(*p));`.
- Malformed matches with no in-bounds alphabetic header token are skipped.
- Header token extraction stops at `match_end`.
- `content=` parsing loops now check `p < match_end` before dereferencing.
- Quoted and unquoted content value scans stop at `match_end`.

This preserves existing behavior for valid META directives while preventing all documented out-of-bounds reads from malformed bounded input.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/filters/mod_proxy_html.c b/modules/filters/mod_proxy_html.c
index 4205a61..cf266e1 100644
--- a/modules/filters/mod_proxy_html.c
+++ b/modules/filters/mod_proxy_html.c
@@ -666,6 +666,7 @@ static meta *metafix(request_rec *r, const char *buf, apr_size_t len)
     size_t offs = 0;
     const char *p;
     const char *q;
+    const char *match_end;
     char *header;
     char *content;
     ap_regmatch_t pmatch[2];
@@ -675,9 +676,14 @@ static meta *metafix(request_rec *r, const char *buf, apr_size_t len)
            !ap_regexec_len(seek_meta, buf + offs, len - offs, 2, pmatch, 0)) {
         header = NULL;
         content = NULL;
+        match_end = buf+offs+pmatch[0].rm_eo;
         p = buf+offs+pmatch[1].rm_eo;
-        while (!apr_isalpha(*++p));
-        for (q = p; apr_isalnum(*q) || (*q == '-'); ++q);
+        while (++p < match_end && !apr_isalpha(*p));
+        if (p >= match_end) {
+            offs += pmatch[0].rm_eo;
+            continue;
+        }
+        for (q = p; q < match_end && (apr_isalnum(*q) || (*q == '-')); ++q);
         header = apr_pstrmemdup(r->pool, p, q-p);
         if (ap_cstr_casecmpn(header, "Content-", 8)) {
             /* find content=... string */
@@ -685,22 +691,24 @@ static meta *metafix(request_rec *r, const char *buf, apr_size_t len)
                               pmatch[0].rm_eo - pmatch[0].rm_so);
             /* if it doesn't contain "content", ignore, don't crash! */
             if (p != NULL) {
-                while (*p) {
+                while (p < match_end) {
                     p += 7;
-                    while (apr_isspace(*p))
+                    while (p < match_end && apr_isspace(*p))
                         ++p;
                     /* XXX Should we search for another content= pattern? */
-                    if (*p != '=')
+                    if (p >= match_end || *p != '=')
+                        break;
+                    while (++p < match_end && apr_isspace(*p));
+                    if (p >= match_end)
                         break;
-                    while (*p && apr_isspace(*++p));
                     if ((*p == '\'') || (*p == '"')) {
                         delim = *p++;
-                        for (q = p; *q && *q != delim; ++q);
+                        for (q = p; q < match_end && *q != delim; ++q);
                         /* No terminating delimiter found? Skip the bogus directive */
-                        if (*q != delim)
+                        if (q >= match_end || *q != delim)
                            break;
                     } else {
-                        for (q = p; *q && !apr_isspace(*q) && (*q != '>'); ++q);
+                        for (q = p; q < match_end && !apr_isspace(*q) && (*q != '>'); ++q);
                     }
                     content = apr_pstrmemdup(r->pool, p, q-p);
                     break;
```