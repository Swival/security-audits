# Host authority mismatch is silently overwritten

## Classification

Validation gap; severity medium; confidence certain

## Affected Locations

`modules/http2/h2_request.c:208`

## Summary

HTTP/2 requests containing both `:authority` and a different `Host` header were accepted. The request finalization path rewrote `Host` to `:authority` before core request validation, hiding the original mismatch from later routing and module logic.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

## Preconditions

An HTTP/2 client sends a request with:

- A populated `:authority` pseudo-header
- A `Host` header
- Different values for `:authority` and `Host`

## Proof

The inbound request path stores client-controlled pseudo-header and regular-header values separately:

- `:authority` populates `req->authority`
- `Host` is stored in `req->headers`

During `h2_request_end_headers()`, when `req->authority` exists, the old behavior unconditionally executed:

```c
apr_table_setn(req->headers, "Host", req->authority);
```

This overwrote the client-supplied `Host` value before later request construction.

The acceptance path then continued:

- `h2_stream_end_headers()` accepted the rewritten request and published it as `stream->request`
- `h2_create_request_rec()` called `assign_headers()`
- `assign_headers()`, `ap_parse_request_line()`, and `ap_check_request_header()` validated only the normalized `Host`

As a result, the malformed mismatch was accepted after being rewritten to `:authority`. The original `Host` was not reliably preserved because `assign_headers()` reads `orig_host` from `req->headers` after `h2_request_end_headers()` has already overwritten it.

## Why This Is A Real Bug

The source comment in `assign_headers()` states that mismatches between `:authority` and `Host` SHOULD be rejected as malformed. The actual behavior did the opposite: it silently normalized the request by overwriting `Host`.

This creates a validation gap because downstream request validation, virtual host selection, and modules observe only the rewritten `Host` value and cannot detect that the original client request contained conflicting authority information.

## Practical Exploit Scenario

A hosting provider runs many vhosts on a single TLS-terminated HTTP/2 listener. Two of them share an IP and certificate:

```apache
<VirtualHost *:443>
    ServerName api.bank.example          ; high value, restricted
    DocumentRoot /srv/api-bank
    <Location "/admin"> Require ip 10.0.0.0/8 </Location>
</VirtualHost>

<VirtualHost *:443>
    ServerName status.bank.example        ; public health checks
    DocumentRoot /srv/status
</VirtualHost>
```

A reverse proxy tier in front of Apache routes to the backend by inspecting the request's `Host` header. WAF rules also key on `Host` (different rule sets for the API versus the status page), and a SIEM correlates traffic by the same field.

An attacker establishes an HTTP/2 connection to the listener using SNI for the status host and sends a HEADERS frame whose pseudo-header and regular-header authorities disagree:

```
:method GET
:scheme https
:path   /admin/internal-keys
:authority api.bank.example
host       status.bank.example
```

`h2_request_end_headers` overwrites `Host` with `:authority`, so Apache binds the request to the high-value `api.bank.example` vhost and serves `/admin/internal-keys` directly from `/srv/api-bank`. Meanwhile the WAF, the access log format `%{Host}i`, and the SIEM all observed the original `host: status.bank.example`, applied the lower-trust rule set, and recorded the request as a benign hit on the status page. The IP-based admin restriction is also bypassed if the front tier applied it on `Host` and Apache trusted the request after rewrite.

The same primitive enables fooling per-vhost auth modules, defeating tenant isolation between co-hosted customers, and smuggling administrative traffic past monitoring under the cover of a public-facing hostname. Detection is hard because the malicious request never appears suspicious in any log keyed on `Host`.

## Fix Requirement

Reject requests with differing `Host` and `:authority` values before overwriting or normalizing the `Host` header.

## Patch Rationale

The patch adds the missing comparison in `h2_request_end_headers()` before `Host` is rewritten. If both values are present and differ, the function returns `APR_BADARG`, causing the malformed request to be rejected instead of accepted and normalized.

This places validation at the earliest point where both original values are still available.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/http2/h2_request.c b/modules/http2/h2_request.c
index 6373e0a..e8b2863 100644
--- a/modules/http2/h2_request.c
+++ b/modules/http2/h2_request.c
@@ -210,6 +210,10 @@ apr_status_t h2_request_end_headers(h2_request *req, apr_pool_t *pool,
         req->authority = host;
     }
     else {
+        const char *host = apr_table_get(req->headers, "Host");
+        if (host && strcmp(req->authority, host)) {
+            return APR_BADARG;
+        }
         apr_table_setn(req->headers, "Host", req->authority);
     }
     req->raw_bytes += raw_bytes;
```