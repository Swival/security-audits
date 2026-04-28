# Cross-Origin Cache Invalidation Ignores Scheme And Port

## Classification

Validation gap, medium severity.

## Affected Locations

- `modules/cache/cache_storage.c:729`
- `modules/cache/cache_storage.c:741`

## Summary

`cache_invalidate()` invalidates cache entries derived from `Location` and `Content-Location` response headers after successful unsafe requests. Before invalidating those derived keys, it only verifies that the request URI hostname matches the header URI hostname.

Because the validation ignores scheme and port, a response for one origin can invalidate a cached entity belonging to another same-host origin on a different scheme or port.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- A successful unsafe request, such as `POST`, `PUT`, or `DELETE`, reaches `cache_invalidate()`.
- The response includes a `Location` or `Content-Location` header.
- The header URI has the same hostname as the request URI.
- The header URI uses a different scheme or port from the request URI.
- A cached entity exists for the header-derived key in the same cache provider.

## Proof

`cache_invalidate()` reads `Location` and `Content-Location` from `r->headers_out`, parses them with `apr_uri_parse()`, and derives cache keys with `cache_canonicalise_key()`.

The vulnerable checks only compare hostnames:

```c
r->parsed_uri.hostname
&& location_uri.hostname
&& !strcmp(r->parsed_uri.hostname, location_uri.hostname)
```

and similarly for `Content-Location`.

However, `cache_canonicalise_key()` includes scheme, hostname, and port in the generated cache key:

```c
*key = apr_pstrcat(p, scheme, "://", hostname, port_str,
                   kpath, "?", kquery, NULL);
```

As a result, an unsafe request for one origin can cause invalidation of a distinct same-host origin.

Example source-level trigger:

```text
POST http://example.com/update
HTTP/1.1 201 Created
Location: http://example.com:8080/victim.css
```

If `http://example.com:8080/victim.css` is cached under the same provider, the host-only validation passes for `example.com`, `location_key` is generated for port `8080`, and the provider opens and invalidates that entity.

The invalidation path is reachable at `modules/cache/cache_storage.c:765`. Disk and socache providers mark the entity invalidated at `modules/cache/mod_cache_disk.c:1380` and `modules/cache/mod_cache_socache.c:1166`. Later cache selection treats invalidated entries as stale at `modules/cache/cache_util.c:603`, forcing revalidation or refetch.

## Why This Is A Real Bug

Origin identity is not defined by hostname alone. Scheme, host, and port together distinguish origins.

The code validates only hostname but then invalidates a key that is canonicalized with scheme and port. This mismatch allows a response from `http://example.com:80` to invalidate `http://example.com:8080`, or a response from one scheme to invalidate the same host under another scheme, provided the cache provider contains the target entry.

This is not merely a logging or accounting issue: the provider state is changed by `invalidate_entity()`, and later cache lookup behavior changes because invalidated entries are considered stale.

## Fix Requirement

Before invalidating cache keys derived from `Location` or `Content-Location`, require equivalence of:

- scheme
- hostname
- effective port

Scheme and hostname comparisons must be case-insensitive. Port comparison must account for explicit ports and scheme default ports.

## Patch Rationale

The patch strengthens the validation in both header-derived invalidation paths.

For `Location`, it now requires:

- `r->parsed_uri.scheme` and `location_uri.scheme` to be present and case-insensitively equal
- `r->parsed_uri.hostname` and `location_uri.hostname` to be present and case-insensitively equal
- the effective request port to equal the effective `Location` port

For `Content-Location`, it applies the same checks against `content_location_uri`.

The effective port is computed as the explicit parsed port when a non-empty `port_str` exists, otherwise `apr_uri_port_of_scheme()` is used for the URI scheme. This prevents default-port forms such as `http://example.com/` and `http://example.com:80/` from being treated as different while still blocking different-port invalidation.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/cache/cache_storage.c b/modules/cache/cache_storage.c
index dfda34b..a644196 100644
--- a/modules/cache/cache_storage.c
+++ b/modules/cache/cache_storage.c
@@ -720,10 +720,22 @@ int cache_invalidate(cache_request_rec *cache, request_rec *r)
                                           location_uri.path,
                                           location_uri.query,
                                           &location_uri, &location_key)
-                || !(r->parsed_uri.hostname
+                || !(r->parsed_uri.scheme
+                     && location_uri.scheme
+                     && !ap_cstr_casecmp(r->parsed_uri.scheme,
+                                         location_uri.scheme)
+                     && r->parsed_uri.hostname
                      && location_uri.hostname
-                     && !strcmp(r->parsed_uri.hostname,
-                                location_uri.hostname))) {
+                     && !ap_cstr_casecmp(r->parsed_uri.hostname,
+                                         location_uri.hostname)
+                     && (((r->parsed_uri.port_str
+                           && r->parsed_uri.port_str[0])
+                          ? r->parsed_uri.port
+                          : apr_uri_port_of_scheme(r->parsed_uri.scheme))
+                         == ((location_uri.port_str
+                              && location_uri.port_str[0])
+                             ? location_uri.port
+                             : apr_uri_port_of_scheme(location_uri.scheme))))) {
             location_key = NULL;
         }
     }
@@ -737,10 +749,22 @@ int cache_invalidate(cache_request_rec *cache, request_rec *r)
                                           content_location_uri.query,
                                           &content_location_uri,
                                           &content_location_key)
-                || !(r->parsed_uri.hostname
+                || !(r->parsed_uri.scheme
+                     && content_location_uri.scheme
+                     && !ap_cstr_casecmp(r->parsed_uri.scheme,
+                                         content_location_uri.scheme)
+                     && r->parsed_uri.hostname
                      && content_location_uri.hostname
-                     && !strcmp(r->parsed_uri.hostname,
-                                content_location_uri.hostname))) {
+                     && !ap_cstr_casecmp(r->parsed_uri.hostname,
+                                         content_location_uri.hostname)
+                     && (((r->parsed_uri.port_str
+                           && r->parsed_uri.port_str[0])
+                          ? r->parsed_uri.port
+                          : apr_uri_port_of_scheme(r->parsed_uri.scheme))
+                         == ((content_location_uri.port_str
+                              && content_location_uri.port_str[0])
+                             ? content_location_uri.port
+                             : apr_uri_port_of_scheme(content_location_uri.scheme))))) {
             content_location_key = NULL;
         }
     }
```