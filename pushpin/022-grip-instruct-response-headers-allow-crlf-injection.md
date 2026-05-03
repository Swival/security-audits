# grip-instruct Response Headers Allow CRLF Injection

## Classification

Header injection, CWE-113, medium severity. Confidence: certain.

## Affected Locations

`src/handler/instruct.cpp:600`

## Summary

`application/grip-instruct` JSON can supply response headers that are appended to `newResponse.headers` without rejecting carriage return or line feed characters. A malicious upstream backend can place CRLF in a JSON `response.headers` name or value, causing injected HTTP response header lines to be emitted by the proxy.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

## Preconditions

- The proxy accepts an `application/grip-instruct` response from a backend.
- The backend response body contains attacker-controlled JSON `response.headers`.
- The attacker can include `\r` or `\n` in a header name or value.

## Proof

A reproduced payload placed CRLF in a grip-instruct response header value, for example:

```json
{
  "response": {
    "headers": [
      ["X-Test", "ok\r\nTransfer-Encoding: chunked"]
    ],
    "body": "hello"
  }
}
```

Observed source flow:

- `Instruct::fromResponse` parses the `application/grip-instruct` JSON.
- `src/handler/instruct.cpp:586` and `src/handler/instruct.cpp:593` read attacker-controlled header name and value strings.
- `src/handler/instruct.cpp:600` appends them as `HttpHeader(name.toUtf8(), val.toUtf8())` without CR/LF validation.
- `handlerengine.cpp` serializes these headers into the accept response.
- `acceptrequest.cpp` reparses them into `out.response.headers` without rejecting embedded CR/LF.
- `src/connmgr/zhttppacket.rs` only requires header names to be UTF-8.
- `src/core/http1/protocol.rs:998` and `src/core/http1/protocol.rs:999` write the header name and value verbatim into the HTTP/1 response.

Impact: embedded CRLF creates additional HTTP response header lines. This can also bypass exact-name stripping of controls such as `Transfer-Encoding` or `Content-Length`, because the injected control appears inside another header value rather than as a separate header object at validation time.

## Why This Is A Real Bug

HTTP/1 response serialization is line-oriented. Header names and values containing CR or LF can terminate the current header line and begin attacker-controlled header lines. The vulnerable path accepts strings from backend-controlled JSON and forwards them into the final HTTP response without sanitization, so the behavior is exploitable whenever an untrusted or compromised backend can return grip-instruct content.

## Fix Requirement

Reject any JSON `response.headers` name or value containing `\r` or `\n` before appending it to `newResponse.headers`.

## Patch Rationale

The patch adds a small `hasLineBreak(const QString &s)` helper and applies it to every grip-instruct JSON response header shape:

- list-form headers: validates both `name` and `val`.
- hash keyed-object headers: validates both `key` and `val`.
- map keyed-object headers: validates both `key` and `val`.

On detection, parsing fails with `header contains invalid character`, preventing contaminated headers from reaching downstream serialization.

## Residual Risk

None

## Patch

```diff
diff --git a/src/handler/instruct.cpp b/src/handler/instruct.cpp
index 615eba42..1029b8b4 100644
--- a/src/handler/instruct.cpp
+++ b/src/handler/instruct.cpp
@@ -83,6 +83,9 @@ static QByteArray unescape(const QByteArray &in) {
 
     return out;
 }
+static bool hasLineBreak(const QString &s) {
+    return s.contains('\r') || s.contains('\n');
+}
 
 Instruct Instruct::fromResponse(const HttpResponseData &response, bool *ok, QString *errorMessage) {
     HoldMode holdMode = NoHold;
@@ -597,6 +600,11 @@ Instruct Instruct::fromResponse(const HttpResponseData &response, bool *ok, QStr
                             return Instruct();
                         }
 
+                        if (hasLineBreak(name) || hasLineBreak(val)) {
+                            setError(ok, errorMessage, "header contains invalid character");
+                            return Instruct();
+                        }
+
                         newResponse.headers += HttpHeader(name.toUtf8(), val.toUtf8());
                     }
                 } else if (isKeyedObject(vheaders)) {
@@ -614,6 +622,11 @@ Instruct Instruct::fromResponse(const HttpResponseData &response, bool *ok, QStr
                                 return Instruct();
                             }
 
+                            if (hasLineBreak(key) || hasLineBreak(val)) {
+                                setError(ok, errorMessage, "header contains invalid character");
+                                return Instruct();
+                            }
+
                             newResponse.headers += HttpHeader(key.toUtf8(), val.toUtf8());
                         }
                     } else // Map
@@ -631,6 +644,11 @@ Instruct Instruct::fromResponse(const HttpResponseData &response, bool *ok, QStr
                                 return Instruct();
                             }
 
+                            if (hasLineBreak(key) || hasLineBreak(val)) {
+                                setError(ok, errorMessage, "header contains invalid character");
+                                return Instruct();
+                            }
+
                             newResponse.headers += HttpHeader(key.toUtf8(), val.toUtf8());
                         }
                     }
```