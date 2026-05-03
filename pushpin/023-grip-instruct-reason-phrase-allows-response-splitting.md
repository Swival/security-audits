# grip-instruct reason phrase allows response splitting

## Classification

Header injection / HTTP response splitting.

Severity: medium.

Confidence: certain.

## Affected Locations

`src/handler/instruct.cpp:568`

Propagation and emission path:

`src/handler/httpsession.cpp:290`

`src/core/zhttprequest.cpp:985`

`src/core/zhttprequest.cpp:986`

`src/core/zhttpresponsepacket.cpp:103`

`src/connmgr/zhttppacket.rs:823`

`src/connmgr/zhttppacket.rs:825`

`src/connmgr/connection.rs:3777`

`src/core/http1/protocol.rs:987`

## Summary

A backend that returns a `200` response with `Content-Type: application/grip-instruct` can place CRLF bytes in JSON `response.reason`.

`Instruct::fromResponse` reads this value with `getString` and assigned it directly to `newResponse.reason`. The value later reaches the HTTP/1 status line and is emitted as raw reason text, allowing an attacker-controlled backend to split the proxied HTTP response.

## Provenance

Found by Swival Security Scanner: https://swival.dev

Reproduced manually from the supplied data-flow evidence and patched in `023-grip-instruct-reason-phrase-allows-response-splitting.patch`.

## Preconditions

- The upstream backend returns status `200`.
- The upstream backend sets `Content-Type: application/grip-instruct`.
- The instruct JSON contains a `response` object.
- The `response.reason` string is attacker-controlled or can contain CRLF.

## Proof

The vulnerable path is:

1. `Instruct::fromResponse` parses `application/grip-instruct` only when the backend response code is `200`.
2. Inside the JSON `response` object, `reason` is read with `getString`.
3. If non-empty, it was assigned directly to `newResponse.reason`.
4. No CR or LF rejection occurred before `i.response = newResponse`.
5. The parsed `instruct.response.reason` is used to start the client response in `src/handler/httpsession.cpp:290`.
6. It is copied into a `ZhttpResponsePacket` at `src/core/zhttprequest.cpp:985` and `src/core/zhttprequest.cpp:986`.
7. It is serialized as a raw reason field at `src/core/zhttpresponsepacket.cpp:103`.
8. The frontend parses it as UTF-8 only at `src/connmgr/zhttppacket.rs:823` and `src/connmgr/zhttppacket.rs:825`.
9. It is passed into response header preparation at `src/connmgr/connection.rs:3777`.
10. The HTTP/1 writer emits it directly in the status line with `write!(writer, "{} {}\r\n", code, reason)` at `src/core/http1/protocol.rs:987`.

A malicious reason such as `OK\r\nInjected-Header: yes\r\n\r\nbody` therefore terminates the status line and injects attacker-controlled response bytes before legitimate headers.

## Why This Is A Real Bug

HTTP/1 status lines are line-oriented. The reason phrase is serialized before `\r\n`; therefore CR or LF inside the reason phrase changes the protocol framing.

The affected value is attacker-controlled through backend instruct JSON, is preserved through the proxy pipeline, and is written directly into the HTTP/1 response. This creates a concrete response splitting/header injection primitive.

## Fix Requirement

Reject `\r` and `\n` in JSON `response.reason` before assigning it to `newResponse.reason`.

The parser must fail the instruct response rather than sanitize by truncation or replacement, because CRLF in a reason phrase is invalid protocol framing input.

## Patch Rationale

The patch validates `reasonStr` immediately after parsing and before conversion to UTF-8 or assignment to `newResponse.reason`.

This is the narrowest effective fix because it blocks the malicious bytes at the trust boundary where `application/grip-instruct` JSON is converted into an internal HTTP response object.

The error uses the existing `setError` pattern and returns `Instruct()` consistently with nearby validation failures.

## Residual Risk

None

## Patch

```diff
diff --git a/src/handler/instruct.cpp b/src/handler/instruct.cpp
index 615eba42..56802971 100644
--- a/src/handler/instruct.cpp
+++ b/src/handler/instruct.cpp
@@ -564,8 +564,15 @@ Instruct Instruct::fromResponse(const HttpResponseData &response, bool *ok, QStr
                 return Instruct();
             }
 
-            if (!reasonStr.isEmpty())
+            if (!reasonStr.isEmpty()) {
+                if (reasonStr.contains('\r') || reasonStr.contains('\n')) {
+                    setError(ok, errorMessage,
+                             QString("%1 contains 'reason' with invalid value").arg(pn));
+                    return Instruct();
+                }
+
                 newResponse.reason = reasonStr.toUtf8();
+            }
 
             if (keyedObjectContains(in, "headers")) {
                 Variant vheaders = keyedObjectGetValue(in, "headers");
```