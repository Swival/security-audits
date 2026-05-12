# CONNECT proxy authorization fails open

## Classification

Authentication bypass, medium severity.

## Affected Locations

`crates/nono-proxy/src/connect.rs:46`

## Summary

`handle_connect` validated `Proxy-Authorization` for CONNECT requests but treated validation failure as non-fatal. Any local process able to reach the proxy listener (the proxy binds to `127.0.0.1` by default) could send a CONNECT with a missing or invalid token and still receive a working tunnel to any host allowed by the filter.

The original fail-open behavior was a deliberate compatibility shim for Node.js undici, which historically did not forward `Proxy-Authorization` from URL userinfo on CONNECT. The shim is too broad: it lets any same-host process bypass the token boundary, including processes outside the sandboxed session that share the loopback interface.

## Provenance

Verified by Swival.dev Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- A local process can reach the proxy listener (loopback by default).
- The requested CONNECT target host passes the configured proxy filter.
- The target host is resolvable and reachable by the proxy.

The sandboxed child already holds the session token via `NONO_PROXY_TOKEN`, so this finding mainly hardens against other same-host processes (a different session, a different user on a shared host, or other code running outside the sandbox). The intercept path at `server.rs:702` already enforces strict auth before minting a leaf — this brings the transparent CONNECT path in line with that policy.

## Proof

A practical trigger is:

```http
CONNECT allowed.example:443 HTTP/1.1
Host: allowed.example:443
```

with no `Proxy-Authorization` header, or with an invalid one.

Execution path:

- `connect::handle_connect` is reached from `crates/nono-proxy/src/server.rs:833`.
- `handle_connect` parses the CONNECT target.
- `token::validate_proxy_auth` returns `Err(InvalidToken)` for missing or invalid authorization at `crates/nono-proxy/src/token.rs:64` and `crates/nono-proxy/src/token.rs:86`.
- `handle_connect` catches the error at `crates/nono-proxy/src/connect.rs:46`, logs `CONNECT auth skipped`, and continues.
- The same unauthenticated request proceeds through `filter.check_host` at `crates/nono-proxy/src/connect.rs:51`.
- If allowed, the proxy connects upstream at `crates/nono-proxy/src/connect.rs:95`.
- The proxy sends `200 Connection Established` at `crates/nono-proxy/src/connect.rs:98`.
- The proxy relays traffic with `copy_bidirectional` at `crates/nono-proxy/src/connect.rs:109`.

Result: an unauthenticated client receives a CONNECT tunnel without a valid session token.

## Why This Is A Real Bug

The source explicitly states CONNECT handling should validate the session token before filtering and tunneling. The helper tests also confirm missing and invalid `Proxy-Authorization` headers return errors. However, the CONNECT handler ignored those errors and continued to establish the tunnel.

This bypasses the proxy authentication boundary: authorization failure does not prevent access to the protected CONNECT capability.

## Fix Requirement

When `validate_proxy_auth` fails for a CONNECT request, the handler must reject the request and stop processing. It must not check the host, connect upstream, send `200 Connection Established`, or relay bytes.

The response should be an HTTP proxy-authentication failure, such as `407 Proxy Authentication Required`.

## Patch Rationale

The patch changes the authentication failure branch from fail-open to fail-closed:

- Logs the authentication failure as `CONNECT auth failed`.
- Sends `407 Proxy Authentication Required`.
- Returns the validation error immediately.
- Prevents all later tunnel-establishment logic from executing.

This preserves valid CONNECT behavior while enforcing the same token boundary already implemented by `token::validate_proxy_auth`.

## Residual Risk

If a real-world undici client relies on the previous lenient behavior for CONNECT, this patch will break it. Sandboxed clients that do not forward the session token on CONNECT must be fixed to inject `Proxy-Authorization` (the token is exported as `NONO_PROXY_TOKEN`). The strict-auth intercept path at `server.rs:702` already imposes the same requirement, so the proxy's own routes do not depend on the shim.

## Patch

```diff
diff --git a/crates/nono-proxy/src/connect.rs b/crates/nono-proxy/src/connect.rs
index 02bdbdd..1e3494f 100644
--- a/crates/nono-proxy/src/connect.rs
+++ b/crates/nono-proxy/src/connect.rs
@@ -41,10 +41,10 @@ pub async fn handle_connect(
     debug!("CONNECT request to {}:{}", host, port);
 
     // Validate session token from Proxy-Authorization header.
-    // Non-fatal for CONNECT: Node.js undici doesn't send Proxy-Authorization
-    // from URL userinfo for CONNECT requests.
     if let Err(e) = validate_proxy_auth(remaining_header, session_token) {
-        debug!("CONNECT auth skipped: {}", e);
+        debug!("CONNECT auth failed: {}", e);
+        send_response(stream, 407, "Proxy Authentication Required").await?;
+        return Err(e);
     }
 
     // Check host against filter (DNS resolution happens here)
```