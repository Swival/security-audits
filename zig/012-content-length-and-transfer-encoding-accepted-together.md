# Content-Length and Transfer-Encoding Accepted Together

## Classification

Request smuggling (CL+TE ambiguity), medium severity.

## Affected Locations

- `lib/std/http/Server.zig:143`
- `Request.Head.parse`
- `Server.receiveHead`, through its use of `Request.Head.parse`

## Summary

`Request.Head.parse` accepted HTTP requests containing both `Content-Length` and `Transfer-Encoding`. It populated both `head.content_length` and `head.transfer_encoding` instead of rejecting the ambiguous framing. Downstream body handling preferred `Transfer-Encoding`, while a front proxy might prefer `Content-Length`, creating a proxy/origin request-boundary disagreement and enabling request smuggling.

## Provenance

Verified and patched from a Swival.dev Security Scanner finding.

Scanner: https://swival.dev

## Preconditions

- The Zig HTTP server parser is used as an origin server.
- The origin is behind a proxy that prefers `Content-Length` when both `Content-Length` and `Transfer-Encoding` are present.
- An unauthenticated client can send raw HTTP requests through that proxy.

## Proof

Before the patch, this request was accepted:

```http
POST /front HTTP/1.1
Host: origin
Content-Length: 37
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: o

```

Observed parser/body behavior:

1. `Server.receiveHead` calls `Request.Head.parse`.
2. `Request.Head.parse` initializes both `content_length` and `transfer_encoding`.
3. The `content-length` branch only rejected duplicate `Content-Length` and parsed the value.
4. The `transfer-encoding` branch only rejected duplicate/unsupported transfer encodings and assigned `head.transfer_encoding`.
5. No check rejected the presence of both fields.
6. `receiveHead` returned a successful `Request`, not `HttpHeadersInvalid`.
7. If the application read or discarded the body, `readerExpectNone` / `discardBody` passed both values into `http.Reader.bodyReader`.
8. `bodyReader` selected `transfer_encoding` first; for `.chunked`, it consumed only the chunked terminator `0\r\n\r\n` and ignored the declared `Content-Length`.

Under a `Content-Length`-preferring proxy, the proxy treats the 37 bytes following the headers as the body of `/front`. The Zig origin accepts the same request head but consumes only the chunked terminator, leaving `GET /admin ...` buffered as the next HTTP request.

## Why This Is A Real Bug

HTTP request framing must be unambiguous at trust boundaries. Accepting both `Content-Length` and `Transfer-Encoding` lets two HTTP components choose different message boundaries. In the reproduced scenario, the proxy and origin disagree about where the first request ends, allowing attacker-controlled bytes to be interpreted by the origin as a second request.

The affected parser explicitly returned both framing fields instead of rejecting the request, and subsequent body handling preferred `Transfer-Encoding`, confirming an exploitable CL+TE desynchronization under the stated precondition.

## Fix Requirement

Reject any request containing both `Content-Length` and `Transfer-Encoding`, regardless of header order.

## Patch Rationale

The patch adds explicit CL+TE rejection in `Request.Head.parse`:

- Tracks whether any `Transfer-Encoding` header has been seen with `has_transfer_encoding`.
- Rejects `Content-Length` if a transfer encoding was already seen.
- Rejects `Transfer-Encoding` if `Content-Length` was already parsed.
- Preserves existing duplicate `Content-Length`, duplicate transfer encoding, and unsupported transfer encoding checks.

The existing parser test was updated so the valid transfer-encoding test case no longer includes `Content-Length`, and it now asserts `content_length == null`.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/std/http/Server.zig b/lib/std/http/Server.zig
index 7820ad6d0d..8bf84aa4a9 100644
--- a/lib/std/http/Server.zig
+++ b/lib/std/http/Server.zig
@@ -131,6 +131,8 @@ pub const Request = struct {
                 },
             };
 
+            var has_transfer_encoding = false;
+
             while (it.next()) |line| {
                 if (line.len == 0) return head;
                 switch (line[0]) {
@@ -150,7 +152,7 @@ pub const Request = struct {
                 } else if (std.ascii.eqlIgnoreCase(header_name, "content-type")) {
                     head.content_type = header_value;
                 } else if (std.ascii.eqlIgnoreCase(header_name, "content-length")) {
-                    if (head.content_length != null) return error.HttpHeadersInvalid;
+                    if (has_transfer_encoding or head.content_length != null) return error.HttpHeadersInvalid;
                     head.content_length = std.fmt.parseInt(u64, header_value, 10) catch
                         return error.InvalidContentLength;
                 } else if (std.ascii.eqlIgnoreCase(header_name, "content-encoding")) {
@@ -164,6 +166,9 @@ pub const Request = struct {
                         return error.HttpTransferEncodingUnsupported;
                     }
                 } else if (std.ascii.eqlIgnoreCase(header_name, "transfer-encoding")) {
+                    if (head.content_length != null) return error.HttpHeadersInvalid;
+                    has_transfer_encoding = true;
+
                     // Transfer-Encoding: second, first
                     // Transfer-Encoding: deflate, chunked
                     var iter = mem.splitBackwardsScalar(u8, header_value, ',');
@@ -201,7 +206,6 @@ pub const Request = struct {
         test parse {
             const request_bytes = "GET /hi HTTP/1.0\r\n" ++
                 "content-tYpe: text/plain\r\n" ++
-                "content-Length:10\r\n" ++
                 "expeCt:   100-continue \r\n" ++
                 "TRansfer-encoding:\tdeflate, chunked \r\n" ++
                 "connectioN:\t keep-alive \r\n\r\n";
@@ -216,7 +220,7 @@ pub const Request = struct {
             try testing.expectEqualStrings("100-continue", req.expect.?);
 
             try testing.expectEqual(true, req.keep_alive);
-            try testing.expectEqual(10, req.content_length.?);
+            try testing.expectEqual(null, req.content_length);
             try testing.expectEqual(.chunked, req.transfer_encoding);
             try testing.expectEqual(.deflate, req.transfer_compression);
         }
```