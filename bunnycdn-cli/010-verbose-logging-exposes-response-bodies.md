# Verbose Logging Exposes Response Bodies

## Classification

Vulnerability, medium severity.

## Affected Locations

`packages/openapi-client/src/middleware.ts:90`

## Summary

Verbose API debugging logged full JSON response bodies to the configured debug sink. Sensitive response fields such as `access_token`, `password`, or other secrets could be exposed in console output, terminal logs, CI logs, or custom `onDebug` collectors.

## Provenance

This finding was verified from the provided source, reproduced with a local runtime PoC, and patched.

Scanner provenance: [Swival Security Scanner](https://swival.dev)

Confidence: certain.

## Preconditions

- `authMiddleware()` is configured with `verbose: true`.
- `authMiddleware()` is configured with an `onDebug` callback.
- The API response JSON contains sensitive fields.

## Proof

`authMiddleware()` enables debug logging only when both `verbose` and `onDebug` are present.

In `onResponse()`, the middleware clones the response, parses the full JSON body, and sends it to the debug sink with:

```ts
debug(`← Body: ${JSON.stringify(body, null, 2)}`);
```

The debug block runs before `if (response.ok) return`, so both successful and error JSON responses are logged before status handling.

A local runtime PoC using `authMiddleware({ verbose: true, onDebug })` with a JSON `Response` containing `access_token` and `password` confirmed that the debug sink received the full secret values.

## Why This Is A Real Bug

Verbose logging is commonly enabled during troubleshooting and in CI or terminal sessions. Because `onDebug` can route messages to arbitrary sinks, the response body can be persisted outside the API client’s intended data flow.

The exposed data originates directly from API responses and is logged without redaction. This creates a practical secret-disclosure path whenever sensitive fields are returned in JSON responses.

## Fix Requirement

Do not log raw API response bodies in verbose mode.

Acceptable fixes include:

- logging response metadata only, or
- redacting sensitive fields before logging response bodies.

## Patch Rationale

The patch preserves useful response debugging by retaining status and status text logging, while preventing disclosure of response contents.

It still attempts to parse the cloned JSON response so the debug output only reports a body marker when a JSON body exists. Instead of serializing the parsed body, it logs a fixed redacted marker:

```ts
debug("← Body: [redacted]");
```

This removes the sensitive-data sink without changing response handling or `ApiError` extraction behavior.

## Residual Risk

None

## Patch

```diff
diff --git a/packages/openapi-client/src/middleware.ts b/packages/openapi-client/src/middleware.ts
--- a/packages/openapi-client/src/middleware.ts
+++ b/packages/openapi-client/src/middleware.ts
@@ -86,8 +86,8 @@ export function authMiddleware(options: ClientOptions): Middleware {
       if (debug) {
         const cloned = response.clone();
         debug(`← ${response.status} ${response.statusText}`);
         try {
-          const body = await cloned.json();
-          debug(`← Body: ${JSON.stringify(body, null, 2)}`);
+          await cloned.json();
+          debug("← Body: [redacted]");
         } catch {}
       }
```