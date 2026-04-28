# Certificate-Controlled OCSP Request Host

## Classification

Trust-boundary violation, medium severity.

## Affected Locations

`modules/ssl/ssl_engine_ocsp.c:159`

## Summary

When `ocsp_force_default` is false, OCSP responder selection trusts the client certificate's AIA OCSP URI. The URI is parsed only for syntactic validity, presence of a hostname, and `http` scheme, then used as the destination for `modssl_dispatch_ocsp_request()`. This lets certificate-controlled data select the outbound OCSP request host, creating a blind SSRF / network-reachability primitive.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

`ocsp_force_default` is false and the certificate contains an OCSP AIA URI.

## Proof

Certificate AIA data flows into `extract_responder_uri()`, which copies the `GEN_URI` string from the certificate. `determine_responder_uri()` uses that value unless a forced default responder is configured.

After `apr_uri_parse()`, the code checks only:

- parse success
- `u->hostname` is present
- `u->scheme` is `http`

The resulting `apr_uri_t` is passed to `modssl_dispatch_ocsp_request()` from `verify_ocsp_status()`. That function resolves and connects to the selected `uri->hostname` and `uri->port` when no OCSP proxy is configured. If `SSLOCSPProxyURL` is configured, the direct TCP next hop is the proxy, but the serialized request still targets the certificate-selected URL and Host header.

The OCSP response can later fail verification, but the outbound HTTP request has already occurred.

## Why This Is A Real Bug

The certificate is untrusted input at the point where OCSP status is being checked. Allowing certificate AIA data to choose the outbound OCSP responder crosses a trust boundary: an attacker who can influence the AIA OCSP URI in a valid certificate can make the server initiate an HTTP POST to an attacker-selected host and port.

This is security-relevant even if final OCSP validation fails, because the network connection and request are made before response validation.

## Fix Requirement

The OCSP request destination must not be selected directly from certificate-controlled AIA data. The implementation must either require a configured responder host or validate any certificate-provided URI against an explicit allowlist.

## Patch Rationale

The patch changes responder selection to always use `sc->server->ocsp_responder` and no longer falls back to `extract_responder_uri(cert, p)`. This removes certificate AIA data from the outbound destination decision and preserves existing URI parsing and scheme checks for the configured responder.

By requiring a configured responder URL, outbound OCSP traffic is constrained to administrator-controlled configuration instead of certificate-controlled metadata.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/ssl/ssl_engine_ocsp.c b/modules/ssl/ssl_engine_ocsp.c
index 5e04512..aef696f 100644
--- a/modules/ssl/ssl_engine_ocsp.c
+++ b/modules/ssl/ssl_engine_ocsp.c
@@ -58,19 +58,9 @@ static apr_uri_t *determine_responder_uri(SSLSrvConfigRec *sc, X509 *cert,
     const char *s;
     apr_status_t rv;
 
-    /* Use default responder URL if forced by configuration, else use
-     * certificate-specified responder, falling back to default if
-     * necessary and possible. */
-    if (sc->server->ocsp_force_default == TRUE) {
-        s = sc->server->ocsp_responder;
-    }
-    else {
-        s = extract_responder_uri(cert, p);
-
-        if (s == NULL && sc->server->ocsp_responder) {
-            s = sc->server->ocsp_responder;
-        }
-    }
+    /* Only use the configured responder URL; certificate AIA data is not
+     * trusted to choose the outbound OCSP request host. */
+    s = sc->server->ocsp_responder;
 
     if (s == NULL) {
         ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, APLOGNO(01918)
```