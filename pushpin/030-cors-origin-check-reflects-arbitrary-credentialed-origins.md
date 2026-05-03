# CORS origin check reflects arbitrary credentialed origins

## Classification

security_control_failure, high severity

## Affected Locations

`src/core/cors.cpp:100`

## Summary

`Cors::applyCorsHeaders` reflected any request `Origin` into `Access-Control-Allow-Origin` while also emitting `Access-Control-Allow-Credentials: true`. Because there was no allowlist, rejection branch, or credentials downgrade, any attacker-controlled origin could receive credentialed browser CORS access.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain

## Preconditions

- `applyCorsHeaders` handles a request with an attacker-controlled `Origin`.
- Automatic cross-origin handling is enabled for the request path.
- The response does not already contain `Access-Control-Allow-Origin`.

## Proof

The vulnerable implementation added `Access-Control-Allow-Credentials: true` when absent, then populated `Access-Control-Allow-Origin` from the request `Origin` when absent.

For a request containing:

```http
Origin: https://attacker.example
```

the response included:

```http
Access-Control-Allow-Origin: https://attacker.example
Access-Control-Allow-Credentials: true
```

The reproduced path showed:

- `Access-Control-Allow-Credentials: true` was added at `src/core/cors.cpp:91`.
- Request `Origin` was read at `src/core/cors.cpp:94`.
- The exact `Origin` value was written as `Access-Control-Allow-Origin` at `src/core/cors.cpp:100`.
- The only fallback was `*` when `Origin` was empty at `src/core/cors.cpp:97`.
- There was no allowlist, comparison, rejection branch, or credentials downgrade for supplied origins.
- The path was reachable through automatic cross-origin handling via `src/proxy/domainmap.cpp:449`, `src/proxy/requestsession.cpp:1005`, and `src/handler/httpsession.cpp:866`.

## Why This Is A Real Bug

Credentialed CORS is an access-control decision. Reflecting an arbitrary `Origin` and pairing it with `Access-Control-Allow-Credentials: true` tells browsers that the attacker-controlled origin is trusted to make credentialed cross-origin reads.

Because remote clients control the `Origin` header, the previous behavior failed open for every supplied origin instead of limiting access to trusted origins.

## Fix Requirement

Do not reflect attacker-controlled origins while credentials are enabled unless the origin has first been validated against an allowlist.

At minimum, automatic CORS handling must avoid producing this unsafe combination:

```http
Access-Control-Allow-Origin: <attacker-controlled origin>
Access-Control-Allow-Credentials: true
```

## Patch Rationale

The patch stops reflecting non-empty request origins by default.

It changes the behavior so that:

- An absent `Access-Control-Allow-Origin` is only auto-filled with `*` when the request `Origin` is empty.
- A supplied request `Origin` is not copied into the response.
- `Access-Control-Allow-Credentials: true` is only added when `Access-Control-Allow-Origin` exists.
- Existing explicit response CORS policy remains respected.

This removes the credentialed arbitrary-origin reflection while preserving the empty-origin fallback behavior.

## Residual Risk

None

## Patch

```diff
diff --git a/src/core/cors.cpp b/src/core/cors.cpp
index 79b8ad8c..adf2ed6a 100644
--- a/src/core/cors.cpp
+++ b/src/core/cors.cpp
@@ -88,18 +88,17 @@ void applyCorsHeaders(const HttpHeaders &requestHeaders, HttpHeaders *responseHe
                 HttpHeader("Access-Control-Expose-Headers", HttpHeaders::join(exposeHeaders));
     }
 
-    if (!responseHeaders->contains("Access-Control-Allow-Credentials"))
-        *responseHeaders += HttpHeader("Access-Control-Allow-Credentials", "true");
-
     if (!responseHeaders->contains("Access-Control-Allow-Origin")) {
         CowByteArray origin = requestHeaders.get("Origin");
 
         if (origin.isEmpty())
-            origin = "*";
-
-        *responseHeaders += HttpHeader("Access-Control-Allow-Origin", origin);
+            *responseHeaders += HttpHeader("Access-Control-Allow-Origin", "*");
     }
 
+    if (!responseHeaders->contains("Access-Control-Allow-Credentials") &&
+        responseHeaders->contains("Access-Control-Allow-Origin"))
+        *responseHeaders += HttpHeader("Access-Control-Allow-Credentials", "true");
+
     if (!responseHeaders->contains("Access-Control-Max-Age"))
         *responseHeaders += HttpHeader("Access-Control-Max-Age", "3600");
 }
```