# SOCKS5 GSSAPI protection negotiation is ignored

## Classification

Cryptographic flaw, medium severity.

Confidence: certain.

## Affected Locations

- `lib/socks_sspi.c:467` (`socks5_sspi_encrypt` accepts any protection byte and logs "BUT NOT USED")
- `lib/socks_sspi.c:472` (returns `CURLE_OK` without storing the protection level)
- `lib/socks.c` SOCKS5 path enforces wrapping only when `conn->socks5_gssapi_enctype` is nonzero
- `lib/socks_gssapi.c` (non-SSPI GSSAPI) does store the protection level for comparison

## Summary

The SOCKS5 GSSAPI SSPI path accepted a proxy-selected integrity or confidentiality protection level, logged that the protection was “BUT NOT USED”, and returned success. Subsequent SOCKS traffic was then sent without SSPI per-message wrapping or verification, despite negotiated protection requiring it.

The patch makes this unsupported state fail closed: if the proxy selects any GSSAPI data protection other than no protection, curl aborts the SOCKS connection.

## Provenance

Reported and reproduced by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- Client uses SOCKS5 GSSAPI SSPI negotiation.
- Proxy completes GSSAPI authentication.
- Proxy returns protection level `1` integrity or `2` confidentiality.

## Proof

`Curl_SOCKS5_gssapi_negotiate` calls `socks5_sspi_encrypt` after SSPI authentication.

Inside `socks5_sspi_encrypt`:

- The proxy protection-level response is read.
- In non-NEC mode, the response is decrypted.
- The selected protection byte is copied into `socksreq`.
- The old code logged `SOCKS5 access with%s protection granted BUT NOT USED.`
- The function returned `CURLE_OK`.

The SSPI path never stored the selected protection level in `conn->socks5_gssapi_enctype`. The non-SSPI GSSAPI path does store it at `lib/socks_gssapi.c:559`.

The later SOCKS guard at `lib/socks.c:1153` only fails when `cf->conn->socks5_gssapi_enctype` is nonzero. Because the SSPI path left that value zero, the guard did not fire and post-auth SOCKS traffic proceeded unwrapped.

## Why This Is A Real Bug

A malicious SOCKS5 proxy with valid GSSAPI credentials can select integrity or confidentiality protection during negotiation. Curl accepted that selected protection level but did not apply SSPI `EncryptMessage` / `DecryptMessage` wrapping to subsequent SOCKS traffic.

That violates the negotiated security semantics. The client believes GSSAPI authentication and protection negotiation succeeded, while the actual post-auth SOCKS stream lacks the negotiated integrity or confidentiality protection.

## Fix Requirement

Either:

- implement SSPI wrapping and verification for all subsequent SOCKS traffic when protection level `1` or `2` is negotiated, or
- fail the connection whenever the proxy selects an unsupported protected mode.

## Patch Rationale

The patch chooses the fail-closed behavior.

If `socksreq[0] != 0`, the proxy selected GSSAPI integrity or confidentiality protection. Because the SSPI SOCKS path does not implement protected post-auth traffic, continuing would silently violate the negotiated protection. The patch returns `CURLE_COULDNT_CONNECT` instead.

If `socksreq[0] == 0`, the negotiated mode is no GSSAPI data protection, which matches the implementation’s actual behavior. The connection may proceed and the log message now accurately states that access without GSSAPI data protection was granted.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/socks_sspi.c b/lib/socks_sspi.c
index cc520a49d0..e90dd16d8a 100644
--- a/lib/socks_sspi.c
+++ b/lib/socks_sspi.c
@@ -464,10 +464,12 @@ static CURLcode socks5_sspi_encrypt(struct Curl_cfilter *cf,
   }
   curlx_free(sspi_w_token[0].pvBuffer);
 
-  infof(data, "SOCKS5 access with%s protection granted BUT NOT USED.",
-        (socksreq[0] == 0) ? "out GSS-API data" :
-        ((socksreq[0] == 1) ? " GSS-API integrity" :
-         " GSS-API confidentiality"));
+  if(socksreq[0] != 0) {
+    failf(data, "SOCKS5 GSS-API data protection is not supported.");
+    return CURLE_COULDNT_CONNECT;
+  }
+
+  infof(data, "SOCKS5 access without GSS-API data protection granted.");
 
   return CURLE_OK;
 }
```