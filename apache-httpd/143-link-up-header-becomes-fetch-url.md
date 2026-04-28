# Link up header becomes fetch URL

## Classification

Trust-boundary violation. Confidence: certain.

## Affected Locations

`modules/md/md_acme_drive.c:219`

## Summary

An ACME server-controlled `Link` header with `rel=up` was accepted as the next certificate-chain retrieval URL without validating that the URL remained on the trusted ACME CA origin. This allowed the ACME response to drive an outbound fetch to an arbitrary absolute URL during certificate chain retrieval.

## Provenance

Verified and reproduced from the provided source and taint-flow evidence. Originally identified by Swival Security Scanner: https://swival.dev

## Preconditions

- ACME server response includes a `Link` header with `rel=up`.
- Certificate chain retrieval proceeds after ACME certificate polling.

## Proof

- `get_up_link()` reads the ACME HTTP response headers and stores `md_link_find_relation(headers, ..., "up")` directly in `ad->chain_up_link`.
- `md_link_find_relation()` returns the raw URI-reference from the `Link` header without constraining scheme, host, or port.
- `get_chain()` later logs `"next chain cert"` and passes `ad->chain_up_link` directly to `md_acme_GET()`.
- `md_acme_GET()` sends the URL through the HTTP stack, where it is preserved and ultimately passed to `CURLOPT_URL`.
- In ACMEv2, this request is made with `get_as_post=1`, so the arbitrary outbound request includes a signed JWS POST body.

## Why This Is A Real Bug

The `Link` header is remote input crossing from the ACME HTTP response into the local client's outbound request target. Because no validation constrained the `rel=up` target to the configured CA origin, a CA response could cause requests to different hosts, different schemes, or internal network addresses. This is a concrete trust-boundary violation and can produce SSRF-like outbound traffic during normal certificate-chain retrieval.

## Fix Requirement

Before using a `rel=up` URL as a fetch target, validate that it belongs to the trusted ACME CA origin. At minimum, the accepted URL must match the configured ACME CA scheme, hostname, and effective port.

## Patch Rationale

The patch adds `same_acme_origin()` and calls it immediately after extracting the `rel=up` link. The helper parses both `acme->url` and the candidate link with `apr_uri_parse()`, rejects malformed or non-absolute URLs, normalizes implicit scheme ports with `apr_uri_port_of_scheme()`, and compares scheme, hostname, and port case-insensitively where appropriate.

If validation fails, the link is logged as ignored and `ad->chain_up_link` is cleared before it can reach `md_acme_GET()`. This blocks arbitrary-origin fetches while preserving same-origin ACME chain retrieval.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/md/md_acme_drive.c b/modules/md/md_acme_drive.c
index 94bcc8a..809ce77 100644
--- a/modules/md/md_acme_drive.c
+++ b/modules/md/md_acme_drive.c
@@ -194,12 +194,37 @@ leave:
 /**************************************************************************************************/
 /* poll cert */
 
+static int same_acme_origin(md_acme_t *acme, const char *url, apr_pool_t *p)
+{
+    apr_uri_t ca_uri, link_uri;
+    apr_port_t ca_port, link_port;
+
+    if (APR_SUCCESS != apr_uri_parse(p, acme->url, &ca_uri)
+        || APR_SUCCESS != apr_uri_parse(p, url, &link_uri)
+        || !ca_uri.scheme || !link_uri.scheme
+        || !ca_uri.hostname || !link_uri.hostname) {
+        return 0;
+    }
+
+    ca_port = ca_uri.port? ca_uri.port : apr_uri_port_of_scheme(ca_uri.scheme);
+    link_port = link_uri.port? link_uri.port : apr_uri_port_of_scheme(link_uri.scheme);
+    return !apr_cstr_casecmp(ca_uri.scheme, link_uri.scheme)
+           && !apr_cstr_casecmp(ca_uri.hostname, link_uri.hostname)
+           && ca_port == link_port;
+}
+
 static void get_up_link(md_proto_driver_t *d, apr_table_t *headers)
 {
     md_acme_driver_t *ad = d->baton;
 
     ad->chain_up_link = md_link_find_relation(headers, d->p, "up");
     if (ad->chain_up_link) {
+        if (!same_acme_origin(ad->acme, ad->chain_up_link, d->p)) {
+            md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, 0, d->p,
+                          "ignoring chain up link from untrusted origin: %s", ad->chain_up_link);
+            ad->chain_up_link = NULL;
+            return;
+        }
         md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, d->p, 
                       "server reports up link as %s", ad->chain_up_link);
     }
```