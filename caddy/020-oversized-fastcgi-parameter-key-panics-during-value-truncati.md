# Oversized FastCGI parameter key panics during value truncation

## Classification

Denial of service, medium severity.

## Affected Locations

`modules/caddyhttp/reverseproxy/fastcgi/writer.go:88`

## Summary

`writePairs` truncates oversized FastCGI parameter values using `vl := maxWrite - 8 - len(k)` and then slices `v[:vl]`. If an attacker-controlled parameter key is longer than `maxWrite - 8`, `vl` becomes negative and Go panics with a slice bounds error. FastCGI reverse proxy requests can place attacker-controlled HTTP header names into FastCGI environment keys, making this reachable by a remote client.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The server is configured to reverse proxy requests through FastCGI.
- FastCGI environment construction forwards attacker-controlled HTTP header names as parameter keys.
- The HTTP request header name is accepted by the frontend HTTP server limits.
- Deployment does not set `max_header_bytes` below the trigger size.

## Proof

FastCGI environment construction copies request headers into environment parameters as `HTTP_` plus the transformed header name. With `maxWrite = 65500`, `writePairs` processes each key/value pair and computes:

```go
vl := maxWrite - 8 - len(k)
v = v[:vl]
```

For a header name of 65,488 bytes, the generated FastCGI parameter key is `HTTP_` plus that name, yielding a 65,493-byte key. Since `maxWrite - 8` is 65,492, `vl` becomes negative. The subsequent `v[:vl]` operation panics at runtime before the request is proxied.

The reproducer verified both the same-package panic path and that Go's default HTTP server accepts such a header name under default header limits.

## Why This Is A Real Bug

The panic is not theoretical: the parameter key length is attacker-influenced through HTTP header names, and the vulnerable arithmetic is performed before any bounds check on the key. A single oversized header name can therefore crash request handling for FastCGI-routed traffic. The failure is caused by unchecked negative slice bounds in normal request serialization code.

## Fix Requirement

Reject or truncate oversized FastCGI parameter keys before computing the value truncation length, ensuring `maxWrite - 8 - len(k)` cannot become negative.

## Patch Rationale

The patch truncates `k` to `maxWrite - 8` before calculating the combined parameter size. This guarantees `vl := maxWrite - 8 - len(k)` is never negative. Existing value truncation behavior is preserved for oversized key/value pairs, while oversized keys no longer trigger a runtime panic.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/caddyhttp/reverseproxy/fastcgi/writer.go b/modules/caddyhttp/reverseproxy/fastcgi/writer.go
index 225d8f5f..70830e51 100644
--- a/modules/caddyhttp/reverseproxy/fastcgi/writer.go
+++ b/modules/caddyhttp/reverseproxy/fastcgi/writer.go
@@ -81,6 +81,9 @@ func (w *streamWriter) writePairs(pairs map[string]string) error {
 	// init headers
 	w.buf.Write(b)
 	for k, v := range pairs {
+		if len(k) > maxWrite-8 {
+			k = k[:maxWrite-8]
+		}
 		m := 8 + len(k) + len(v)
 		if m > maxWrite {
 			// param data size exceed 65535 bytes"
```