# HTTPS Proxy CONNECT Rejection Downgrades HTTPS Requests to Proxy Plaintext

## Classification

Information disclosure, medium severity.

## Affected Locations

- `lib/std/http/Client.zig:1346`
- `lib/std/http/Client.zig`: `connect()`, `connectProxied()`, and `Request.sendHead()`

## Summary

When an HTTPS proxy rejects `CONNECT`, the client falls back to normal HTTP proxying. For an HTTPS target, this causes the client to send the full absolute-form HTTPS request, headers, and body to the proxy instead of failing the request.

## Provenance

Verified by Swival security analysis and reproduction.

Scanner: [https://swival.dev](https://swival.dev)

Confidence: certain.

## Preconditions

- `client.https_proxy` is configured.
- The client sends an HTTPS request.
- The configured HTTPS proxy rejects `CONNECT` with a non-`200` response.

## Proof

For an HTTPS URI, `request()` resolves the target protocol as `.tls` and calls `connect()`.

`connect()` selects `client.https_proxy` and attempts `connectProxied()`. If the proxy returns any non-`200` response to `CONNECT`, `connectProxied()` maps the failure to `error.TunnelNotSupported`.

Before the patch, `connect()` caught `error.TunnelNotSupported`, exited the tunnel path, opened a normal connection to the proxy, and set:

```zig
connection.proxied = true;
```

Then `sendHead()` observed `connection.proxied` and emitted an absolute-form request URI:

```http
POST https://victim.example/secret HTTP/1.1
host: victim.example
...
```

The request body is then written to the same connection by `sendBodyUnflushed()` / `fetch()`.

No TLS-to-origin layer is created after the failed `CONNECT`; any TLS in use is only the proxy connection’s own protocol. Therefore the proxy receives the application HTTP request contents.

Practical trigger:

```http
HTTP/1.1 403 Forbidden
```

as the proxy response to `CONNECT victim.example:443`.

Impact:

- The proxy sees the HTTPS request line.
- The proxy sees headers emitted by the client.
- The proxy sees the request body.

## Why This Is A Real Bug

An HTTPS proxy is expected to see only the `CONNECT` authority and then tunnel opaque TLS traffic to the origin. Replacing a failed tunnel with ordinary proxying violates HTTPS confidentiality expectations and discloses application-layer request data to the proxy.

A malicious or compromised configured HTTPS proxy can deterministically trigger the bug by rejecting `CONNECT`.

## Fix Requirement

For HTTPS targets, `CONNECT` rejection must fail the request. The client must never fall back to normal HTTP proxying for `.tls` target requests.

## Patch Rationale

The patch adds an explicit guard after the failed tunnel path in `connect()`:

```zig
if (protocol == .tls) return error.ConnectionRefused;
```

This preserves fallback behavior for plain HTTP targets while preventing HTTPS requests from being retried as normal proxied plaintext requests.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/std/http/Client.zig b/lib/std/http/Client.zig
index 1dd8bb6579..d8c2a8789a 100644
--- a/lib/std/http/Client.zig
+++ b/lib/std/http/Client.zig
@@ -1615,6 +1615,8 @@ pub fn connect(
         };
     }
 
+    if (protocol == .tls) return error.ConnectionRefused;
+
     // fall back to using the proxy as a normal http proxy
     const connection = try client.connectTcp(proxy.host, proxy.port, proxy.protocol);
     connection.proxied = true;
```