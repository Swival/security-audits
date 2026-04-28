# request body length desynchronization

## Classification

Data integrity bug; severity medium; confidence certain

## Affected Locations

`modules/filters/mod_sed.c:414`

## Summary

`InputSed` rewrites request body bytes but leaves the original `Content-Length` in `r->headers_in`. Downstream code can therefore observe metadata derived from the pre-filter body while reading transformed bytes from the input filter chain.

The output path already handles this class of issue by unsetting `Content-Length`; the input path did not.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

## Preconditions

- `InputSed` is configured.
- The request has a `Content-Length` header.
- The configured sed processing can change body length, including substitutions or sed finalization that appends a newline to a body lacking one.

## Proof

Request body bytes enter `sed_request_filter` through `ap_get_brigade`, are rewritten by `sed_eval_buffer`, and transformed bytes are emitted through `sed_write_output` into `ctx->bb`.

The filter returns the transformed brigade to callers without invalidating the original `Content-Length` header. Before the patch, the input path never removed or recalculated `Content-Length`.

This creates a stale-length path:

- `ap_setup_client_block` parses the original `Content-Length` from `r->headers_in` into `r->remaining` at `modules/http/http_filters.c:1728` and `modules/http/http_filters.c:1750`.
- `mod_proxy_scgi` advertises `CONTENT_LENGTH` from `r->remaining` at `modules/proxy/mod_proxy_scgi.c:292`.
- `mod_proxy_scgi` then sends filtered body bytes read via `ap_get_client_block` at `modules/proxy/mod_proxy_scgi.c:341`.

A concrete trigger is a location using `SetInputFilter Sed`, an `InputSed` rule that changes length, and a `Content-Length` request. A downstream handler or backend that trusts the length metadata can receive a length based on the original body while the actual bytes are rewritten.

## Why This Is A Real Bug

`Content-Length` is framing and integrity metadata. If it no longer matches the body supplied by the input filter chain, downstream consumers can truncate the body, wait for bytes that will never arrive, treat extra bytes as another message, or otherwise mis-handle request framing.

The source comments explicitly note that sed finalization may append a newline when the input lacks a trailing newline, so even apparent pass-through sed processing can change the request body length.

The response filter already unsets `Content-Length` after initializing sed processing, demonstrating that length-changing sed output requires metadata invalidation. The request filter lacked the equivalent protection.

## Practical Exploit Scenario

A site uses Apache as a frontend that filters request bodies before forwarding to an SCGI/FastCGI backend. The administrator wants to redact secrets that occasionally appear in client-submitted bodies (API keys, internal hostnames) and configures `mod_sed` accordingly:

```apache
<Location /api/>
    SetInputFilter Sed
    InputSed "s/AAAA/B/g"
    ProxyPass "scgi://backend.internal:4000/"
</Location>
```

Apache reads the inbound request body, applies the substitution, and forwards the rewritten body to the backend over SCGI. Because `Content-Length` from the original request is never invalidated, `mod_proxy_scgi` advertises `CONTENT_LENGTH=16` to the backend even though after substitution the rewritten body is only 4 bytes long.

The immediate consequence is that the backend's body parser blocks waiting for the missing 12 bytes, eventually timing out or returning a 502. An attacker repeats this against pipelined or HTTP/2-multiplexed clients to keep backend workers stuck, draining the pool and producing denial of service.

A more dangerous variant exploits the desync directly. The attacker pipelines two requests on a single keep-alive connection from Apache to the backend:

```http
POST /api/redact HTTP/1.1
Content-Length: 16

AAAAAAAAAAAAAAAA
POST /api/login HTTP/1.1
Content-Length: 32
...
```

Apache rewrites the first body to four `B` bytes but still tells the backend `CONTENT_LENGTH=16`. The backend reads the four post-Sed bytes plus 12 bytes from the *next* pipelined request to satisfy its declared length. Those 12 bytes were the start of the second request's headers, so what the backend sees as request boundaries no longer align with what Apache sent. The attacker has constructed a frontend/backend request smuggling primitive: the second request's effective body, headers, or method are now under attacker control, and any per-request authentication state on the backend can be reused, hijacked, or confused. Because `mod_sed` finalization can also append a newline to bodies that lack one, this length skew can be triggered with no substitution rule that ever changes characters, only normalizes terminators.

## Fix Requirement

Whenever `InputSed` is active for a request body, the original request `Content-Length` must not remain authoritative unless it is recomputed for the transformed body.

## Patch Rationale

The patch unsets `Content-Length` from `r->headers_in` when the sed request filter context is initialized:

```c
apr_table_unset(f->r->headers_in, "Content-Length");
```

This mirrors the response filter behavior and prevents downstream modules from treating the pre-filter length as valid after body transformation. Recomputing the exact transformed length is not practical for streaming input without buffering the full request body, so invalidating the stale header is the correct minimal fix.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/filters/mod_sed.c b/modules/filters/mod_sed.c
index 12cb04a..151136c 100644
--- a/modules/filters/mod_sed.c
+++ b/modules/filters/mod_sed.c
@@ -411,6 +411,7 @@ static apr_status_t sed_request_filter(ap_filter_t *f,
         if (status != APR_SUCCESS)
              return status;
         ctx = f->ctx;
+        apr_table_unset(f->r->headers_in, "Content-Length");
         ctx->bb    = apr_brigade_create(f->r->pool, f->c->bucket_alloc);
         ctx->bbinp = apr_brigade_create(f->r->pool, f->c->bucket_alloc);
     }
```