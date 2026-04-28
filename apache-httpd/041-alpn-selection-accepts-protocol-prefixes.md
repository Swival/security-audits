# ALPN selection accepts protocol prefixes

## Classification

Validation gap; medium severity; confidence certain.

## Affected Locations

`modules/ssl/ssl_engine_io.c:1398`

## Summary

The proxy-side ALPN verification accepted a backend-selected protocol when it was only a prefix of one of Apache's proposed protocols. The check used `strncmp(selected, proto, slen)` where `slen` is the backend-selected ALPN length, but it did not require the proposed protocol to have the same length. A backend selecting `h` could therefore match a proposed `h2`, causing the proxy connection to proceed with an unproposed ALPN value.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

## Preconditions

A proxy backend returns an ALPN string that shares a prefix with one of Apache's proposed protocols but is shorter than the proposed protocol.

## Proof

`ssl_io_filter_handshake()` retrieves the backend-selected ALPN bytes and length using `SSL_get0_alpn_selected()`.

When Apache has proposed ALPN protocols, the code iterates over `alpn_proposed` and previously checked each candidate with:

```c
found = !strncmp(selected, proto, slen);
```

Because `slen` is the selected protocol length, this accepts prefix matches. For example:

```c
selected = "h";
slen = 1;
proto = "h2";

strncmp("h", "h2", 1) == 0
```

This sets `found` to true even though `h` was never proposed. The `"none of our proposals"` branch is skipped, `proxy_ssl_check_peer_ok` remains true, and the proxy connection can continue.

## Why This Is A Real Bug

The surrounding code explicitly states that a backend selecting none of Apache's ALPN proposals must be treated as an error "for security reasons." The old comparison failed to enforce exact ALPN identity and instead enforced only prefix equality in the shorter-selected case. That permits an unproposed backend protocol to pass the validation gate.

## Fix Requirement

Accept a selected ALPN protocol only when both conditions hold:

1. The selected protocol length equals the proposed protocol length.
2. The selected protocol bytes equal the proposed protocol bytes.

## Patch Rationale

The patch adds exact length equality before the byte comparison:

```c
found = (slen == strlen(proto) && !strncmp(selected, proto, slen));
```

This preserves the existing byte comparison while preventing shorter selected ALPN identifiers from matching longer proposed identifiers by prefix.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/ssl/ssl_engine_io.c b/modules/ssl/ssl_engine_io.c
index 0be5318..968d751 100644
--- a/modules/ssl/ssl_engine_io.c
+++ b/modules/ssl/ssl_engine_io.c
@@ -1395,7 +1395,7 @@ static apr_status_t ssl_io_filter_handshake(ssl_filter_ctx_t *filter_ctx)
                 int i, found = 0;
                 for (i = 0; !found && i < alpn_proposed->nelts; ++i) {
                     proto = APR_ARRAY_IDX(alpn_proposed, i, const char *);
-                    found = !strncmp(selected, proto, slen);
+                    found = (slen == strlen(proto) && !strncmp(selected, proto, slen));
                 }
                 if (!found) {
                     /* From a conforming peer, this should never happen,
```