# Redirect Userinfo Overflows Fixed Basic Auth Buffer

## Classification

Denial of service, medium severity.

## Affected Locations

- `lib/std/http/Client.zig:1147`
- `lib/std/http/Client.zig:1371-1374`
- `lib/std/http/Client.zig:1402-1410`

## Summary

A malicious HTTP server can crash a Zig HTTP client that follows redirects by returning a `Location` URI with oversized userinfo. Redirect handling accepts the attacker-controlled URI, later emits default Basic authorization from `uri.user` / `uri.password`, and writes the decoded userinfo into a fixed 511-byte stack buffer. Oversized userinfo causes `Writer.fixed` to fail, but the failure is caught as `unreachable`, producing a panic/abort.

## Provenance

Verified and patched from a Swival.dev Security Scanner finding.

Scanner URL: https://swival.dev

## Preconditions

- Automatic redirects are enabled.
- The supplied redirect buffer is large enough to accept the malicious `Location` value.
- The redirected URI contains `user` or `password` userinfo longer than the Basic auth fixed-buffer limits.

## Proof

Concrete trigger:

1. Victim performs a GET/fetch with redirects enabled.
2. Attacker-controlled server returns a redirect response, for example:
   - `302 Found`
   - `Location: http://<512 bytes of user>@attacker-host/`
3. The `Location` length is below the redirect buffer limit, such as the default 8192 bytes.
4. `receiveHead` follows the redirect and calls `redirect`.
5. `redirect` copies the attacker-controlled `Location`, resolves it into `r.uri`, connects to the redirected host, and prepares the redirected request.
6. `receiveHead` calls `sendBodiless` for the redirected request.
7. `sendHead` sees `uri.user != null or uri.password != null` and emits default `authorization:`.
8. `basic_authorization.write` uses:

   ```zig
   var buf: [max_user_len + 1 + max_password_len]u8 = undefined;
   var w: Writer = .fixed(&buf);
   user.formatUser(&w) catch unreachable;
   w.writeByte(':') catch unreachable;
   password.formatPassword(&w) catch unreachable;
   ```

9. With a 512-byte username, the fixed buffer is exhausted.
10. `Writer.fixed` returns `error.WriteFailed`.
11. The error is caught as `unreachable`, causing a process panic/abort.

Impact: attacker-triggered client process denial of service.

## Why This Is A Real Bug

The input is attacker-controlled through an HTTP redirect `Location` header. The redirect path validates only redirect-buffer capacity and URI syntax before accepting the URI. Later header generation assumes Basic auth userinfo fits `basic_authorization.max_user_len` and `max_password_len`, but that assumption is not enforced for redirected URIs. Because write failures are marked `unreachable`, ordinary oversized network input becomes a process crash rather than a recoverable error.

## Fix Requirement

Reject redirected URIs whose formatted `user` or `password` component exceeds the fixed Basic authorization limits, or replace the fixed Basic auth buffer with dynamically sized allocation.

## Patch Rationale

The patch rejects oversized redirected userinfo immediately after redirect URI resolution and before opening the redirected connection or sending the redirected request. It computes the formatted user and password lengths using `Writer.Discarding`, matching the formatting path used by Basic authorization, then returns `error.HttpRedirectLocationInvalid` when either component exceeds the fixed limits.

This preserves the existing fixed-buffer Basic auth implementation while ensuring redirected attacker-controlled userinfo cannot reach the `catch unreachable` fixed-buffer writes.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/std/http/Client.zig b/lib/std/http/Client.zig
index 1dd8bb6579..587e70ef4f 100644
--- a/lib/std/http/Client.zig
+++ b/lib/std/http/Client.zig
@@ -1224,6 +1224,16 @@ pub const Request = struct {
             error.InvalidHostName => return error.HttpRedirectLocationInvalid,
             error.NoSpaceLeft => return error.HttpRedirectLocationOversize,
         };
+        if (new_uri.user) |user| if (user_len: {
+            var dw: Writer.Discarding = .init(&.{});
+            user.formatUser(&dw.writer) catch unreachable; // discarding
+            break :user_len dw.count + dw.writer.end;
+        } > basic_authorization.max_user_len) return error.HttpRedirectLocationInvalid;
+        if (new_uri.password) |password| if (password_len: {
+            var dw: Writer.Discarding = .init(&.{});
+            password.formatPassword(&dw.writer) catch unreachable; // discarding
+            break :password_len dw.count + dw.writer.end;
+        } > basic_authorization.max_password_len) return error.HttpRedirectLocationInvalid;
 
         const protocol = Protocol.fromUri(new_uri) orelse return error.UnsupportedUriScheme;
         const old_connection = r.connection.?;
```