# Verbose Logging Exposes Request Bodies

## Classification

Medium severity vulnerability.

## Affected Locations

`packages/openapi-client/src/middleware.ts:72`

## Summary

When verbose logging is enabled, `authMiddleware` logs full JSON request bodies through `onDebug`. Request bodies can contain secrets such as Edge Script secret values and registry passwords, causing sensitive values to be exposed in debug output.

## Provenance

Verified from the provided source, reproducer summary, and patch.

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

Verbose logging is enabled.

`onDebug` is configured and receives debug log messages.

A caller sends a request body containing sensitive JSON fields such as `Secret`, `password`, or credential objects.

## Proof

`authMiddleware` enables debug logging when `verbose && onDebug` is true.

In `packages/openapi-client/src/middleware.ts`, `onRequest` checks `request.body`, clones the request, parses the full JSON body with `cloned.json()`, and sends `JSON.stringify(body, null, 2)` to `debug`.

This makes caller-controlled request bodies reachable in logs without redaction.

Practical sensitive sources include:

- `packages/cli/src/commands/scripts/env/set.ts:183`, which sends `{ Name, Secret: value }` for Edge Script secrets.
- `packages/cli/src/commands/registries/add.ts:95`, which sends `passwordCredentials: { userName, password }`.

Commands such as `bunny scripts env set API_KEY sk-... --secret --verbose` or registry add with `--verbose` can therefore print raw secrets or passwords into debug logs.

## Why This Is A Real Bug

Verbose logs are often copied into terminals, CI logs, issue reports, support bundles, or shared debugging output. Logging complete request bodies exposes authentication material and secret configuration values outside their intended storage path.

The exposure is not theoretical because existing CLI commands send sensitive request fields through this middleware, and the middleware logs the parsed body whenever verbose mode is active.

## Fix Requirement

Do not log raw request bodies in verbose mode.

Either redact sensitive fields before logging or log only non-sensitive metadata. The patch implements the safer metadata-only behavior by replacing request body contents with a fixed redacted marker.

## Patch Rationale

The patch removes JSON parsing and serialization of request bodies from the debug path.

Instead of cloning the request and logging the parsed body, the middleware now logs:

```ts
debug("→ Body: [redacted]");
```

This preserves useful debug signal that a request body was present while preventing accidental disclosure of secrets, passwords, tokens, or other sensitive request fields.

## Residual Risk

None

## Patch

```diff
diff --git a/packages/openapi-client/src/middleware.ts b/packages/openapi-client/src/middleware.ts
--- a/packages/openapi-client/src/middleware.ts
+++ b/packages/openapi-client/src/middleware.ts
@@ -72,11 +72,7 @@ export function authMiddleware(options: ClientOptions): Middleware {
       if (debug) {
         debug(`→ ${request.method} ${request.url}`);
         if (request.body) {
-          const cloned = request.clone();
-          try {
-            const body = await cloned.json();
-            debug(`→ Body: ${JSON.stringify(body, null, 2)}`);
-          } catch {}
+          debug("→ Body: [redacted]");
         }
       }

```