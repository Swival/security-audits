# Conflicting Content-Length Headers Accepted

## Classification

- Type: Request smuggling
- Severity: Medium
- Confidence: Certain

## Affected Locations

- `lib/http1.c:396`
- Function: `init_headers`

## Summary

HTTP/1 request parsing accepted multiple `Content-Length` headers with different values. The implementation selected the first `Content-Length` header and ignored later conflicting values. If a frontend forwards duplicate `Content-Length` headers but frames the request body using a different value, H2O can disagree with the frontend about request boundaries, enabling HTTP request smuggling on persistent backend connections.

## Provenance

- Verified by Swival.dev Security Scanner: https://swival.dev
- Reproduced from source review and request-boundary analysis.
- Patch supplied as `012-conflicting-content-length-headers-are-accepted.patch`.

## Preconditions

- A frontend proxy forwards duplicate `Content-Length` headers to H2O.
- The frontend frames the request body using a different duplicate `Content-Length` value than H2O selects.
- The backend HTTP/1 connection is persistent.

## Proof

`init_headers` records a `Content-Length` only when `*entity_header_index == -1`, so the first `Content-Length` wins. Later duplicate `Content-Length` headers are neither compared nor rejected.

`handle_incoming_request` passes only the selected header to `create_entity_reader`, which parses that value and creates a content-length reader. The reader consumes exactly that number of bytes. Extra bytes remain buffered and can be parsed as the next request on the same persistent HTTP/1 connection.

Practical trigger:

```http
POST /first HTTP/1.1
Host: victim
Content-Length: 5
Content-Length: 46

ABCDEGET /smuggled HTTP/1.1
Host: victim

```

If the frontend uses `Content-Length: 46`, it treats `GET /smuggled` as body bytes for `/first`. H2O uses `Content-Length: 5`, consumes only `ABCDE`, leaves the embedded `GET` in the socket buffer, and later parses it as a second request.

## Why This Is A Real Bug

HTTP request smuggling occurs when frontend and backend disagree on message boundaries. The affected code allowed exactly that disagreement by accepting conflicting duplicate `Content-Length` values and silently choosing one. H2O also defaults HTTP/1.1 requests to keep-alive, and buffered bytes are parsed as the next request after cleanup, making the boundary desynchronization exploitable under the stated frontend condition.

## Fix Requirement

Reject duplicate `Content-Length` headers unless all observed values are identical.

## Patch Rationale

The patch checks each newly observed `Content-Length` header against previous `Content-Length` headers during header initialization. If any prior value differs, parsing fails with `"conflicting content-length headers"`. Identical duplicate values remain accepted, preserving compatibility while eliminating ambiguous framing.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/http1.c b/lib/http1.c
index c6e9c1e7b..166db49f7 100644
--- a/lib/http1.c
+++ b/lib/http1.c
@@ -391,6 +391,12 @@ static const char *init_headers(h2o_mem_pool_t *pool, h2o_headers_t *headers, co
                         host->base = (char *)src[i].value;
                         host->len = src[i].value_len;
                     } else if (name_token == H2O_TOKEN_CONTENT_LENGTH) {
+                        size_t j;
+                        for (j = 0; j != i; ++j) {
+                            if (src[j].name_len == src[i].name_len && h2o_memis(src[j].name, src[j].name_len, H2O_STRLIT("content-length")) &&
+                                !h2o_memis(src[j].value, src[j].value_len, src[i].value, src[i].value_len))
+                                return "conflicting content-length headers";
+                        }
                         if (*entity_header_index == -1)
                             *entity_header_index = i;
                     } else if (name_token == H2O_TOKEN_TRANSFER_ENCODING) {
```