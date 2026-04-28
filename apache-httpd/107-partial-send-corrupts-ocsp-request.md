# Partial Send Corrupts OCSP Request

## Classification

Data integrity bug, high severity.

## Affected Locations

`modules/ssl/ssl_util_ocsp.c:134`

## Summary

`send_request` incorrectly advances the OCSP request write pointer by the previous remaining byte count instead of the number of bytes actually written. If `apr_socket_send` performs a successful partial write, the loop skips unsent bytes and sends later or out-of-buffer data, corrupting the OCSP HTTP request.

## Provenance

Verified from the supplied source, reproducer summary, and patch.

Originally reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

`apr_socket_send` writes fewer bytes than requested without returning an error.

## Proof

`modssl_dispatch_ocsp_request` serializes the OCSP HTTP request with `serialize_request`, then always sends it through `send_request`.

Inside `send_request`, each `BIO_read` chunk is sent in a loop:

```c
apr_size_t wlen = remain;

rv = apr_socket_send(sd, wbuf, &wlen);
wbuf += remain;
remain -= wlen;
```

`apr_socket_send` updates `wlen` to the number of bytes actually written. When `wlen < remain`, `remain` still contains the old requested length at the time `wbuf` is advanced.

Example:

- Initial `remain = 100`
- `apr_socket_send` writes `wlen = 40`
- Code advances `wbuf` by `100`
- Code subtracts `40`, leaving `remain = 60`
- Next send starts from `buf + 100`, skipping `buf + 40..99`

The responder therefore receives a corrupted OCSP HTTP request. For full-size chunks, the next send may also read past the populated region of `buf`.

## Why This Is A Real Bug

The loop invariant is that `wbuf` must point to the first unsent byte and `remain` must track the number of unsent bytes. Advancing by the old `remain` violates that invariant after any successful partial send.

This path is used for OCSP dispatch by `modssl_dispatch_ocsp_request`, including certificate OCSP checking and stapling renewal. Corrupted requests can cause responder errors, unknown OCSP results, or OCSP/stapling failures depending on configuration.

## Fix Requirement

Advance `wbuf` by `wlen`, then subtract `wlen` from `remain`.

## Patch Rationale

The patch changes the pointer increment to use the actual byte count reported by `apr_socket_send`:

```diff
-            wbuf += remain;
+            wbuf += wlen;
             remain -= wlen;
```

This restores the required invariant:

- `wbuf` advances only over bytes confirmed written
- `remain` decreases by the same confirmed written count
- retry sends begin at the first unsent byte

## Residual Risk

None

## Patch

```diff
diff --git a/modules/ssl/ssl_util_ocsp.c b/modules/ssl/ssl_util_ocsp.c
index a202a72..9dd12cf 100644
--- a/modules/ssl/ssl_util_ocsp.c
+++ b/modules/ssl/ssl_util_ocsp.c
@@ -133,7 +133,7 @@ static apr_socket_t *send_request(BIO *request, const apr_uri_t *uri,
             apr_size_t wlen = remain;

             rv = apr_socket_send(sd, wbuf, &wlen);
-            wbuf += remain;
+            wbuf += wlen;
             remain -= wlen;
         } while (rv == APR_SUCCESS && remain > 0);

```