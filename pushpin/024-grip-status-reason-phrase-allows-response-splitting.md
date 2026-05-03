# Grip-Status reason phrase allows response splitting

## Classification

Header injection / HTTP response splitting.

Severity: medium.

Confidence: certain.

## Affected Locations

`src/handler/instruct.cpp:237`

## Summary

`Instruct::fromResponse` trusted the reason phrase portion of an upstream `Grip-Status` header and copied it into `newResponse.reason` without rejecting carriage return or line feed bytes. When the proxy later serialized that response as an HTTP/1 status line, embedded CRLF bytes terminated the status line early and injected attacker-controlled downstream response headers.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched from the provided scanner result, source code, and byte-level propagation evidence.

## Preconditions

- The proxy consumes upstream `Grip-Status` instructions.
- An attacker can influence a backend response header such as `Grip-Status`.
- The downstream response is serialized through an HTTP status-line writer that uses `newResponse.reason`.

## Proof

A malicious upstream backend returns:

```http
Grip-Status: 200 OK\r\nX-Injected: yes
```

The reproduced flow is:

- `src/handler/instruct.cpp:222` reads `Grip-Status`.
- `src/handler/instruct.cpp:227` splits the value at the first space.
- `src/handler/instruct.cpp:242` assigns the remainder directly to `newResponse.reason`.
- `src/handler/handlerengine.cpp:859` returns the crafted response.
- `src/proxy/proxysession.cpp:1295` uses the returned response.
- `src/proxy/requestsession.cpp:1012` passes it to the zhttp response path.
- `src/core/http1/protocol.rs:987` writes `"{code} {reason}\r\n"` directly.
- `src/m2adapter/m2adapterapp.cpp:103` has the same raw status-line construction.

Resulting downstream bytes include an injected header:

```http
HTTP/1.1 200 OK\r\n
X-Injected: yes\r\n
...
```

## Why This Is A Real Bug

HTTP reason phrases are serialized in the status line. CR or LF inside the reason phrase changes the wire format by ending the status line and beginning attacker-controlled header lines. The value originates from a backend-controlled `Grip-Status` instruction and bypasses normal response-header filtering because it is not represented as a normal header by the time it reaches the sink.

## Fix Requirement

Reject or strip CR and LF from `Grip-Status` reason phrases before assigning them to `newResponse.reason`.

## Patch Rationale

The patch rejects any `Grip-Status` reason phrase containing `\r` or `\n` immediately after status-code validation and before assignment to `newResponse.reason`. This prevents status-line control characters from propagating to downstream HTTP serializers while preserving valid `Grip-Status` behavior.

## Residual Risk

None

## Patch

```diff
diff --git a/src/handler/instruct.cpp b/src/handler/instruct.cpp
index 615eba42..71564211 100644
--- a/src/handler/instruct.cpp
+++ b/src/handler/instruct.cpp
@@ -239,6 +239,11 @@ Instruct Instruct::fromResponse(const HttpResponseData &response, bool *ok, QStr
             return Instruct();
         }
 
+        if (reason.contains('\r') || reason.contains('\n')) {
+            setError(ok, errorMessage, "Grip-Status contains invalid reason phrase");
+            return Instruct();
+        }
+
         newResponse.reason = reason;
     }
```