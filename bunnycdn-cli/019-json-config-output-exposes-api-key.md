# JSON Config Output Exposes API Key

## Classification

Vulnerability, medium severity.

## Affected Locations

`packages/cli/src/commands/config/show.ts:14`

## Summary

The `config show` command exposed the raw configured API key when invoked with JSON output. The non-JSON output path already masks the API key, but the JSON path serialized the full resolved configuration object directly.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- A user runs `config show` with `output=json`.
- An API key is configured through command arguments or configuration sources.

## Proof

`packages/cli/src/commands/config/show.ts:10` resolves configuration with `resolveConfig(profile, apiKey)`. The resolved configuration contains the raw `apiKey`.

When `output === "json"`, `packages/cli/src/commands/config/show.ts:14` logs:

```ts
JSON.stringify(cfg, null, 2)
```

Because `cfg` includes `apiKey`, stdout contains the secret directly, for example:

```json
{
  "apiKey": "SECRET_ENV_KEY_123456789",
  "profile": ""
}
```

The non-JSON path masks the same value at `packages/cli/src/commands/config/show.ts:25`, demonstrating that the command already treats the API key as sensitive.

## Why This Is A Real Bug

The API key can be exposed to terminal scrollback, shell redirection, CI logs, build logs, or downstream processes consuming JSON output. This violates the command’s existing secret-handling behavior because the non-JSON path redacts the same sensitive field.

## Fix Requirement

Redact or omit `cfg.apiKey` before passing configuration data to `JSON.stringify`.

## Patch Rationale

The patch preserves the JSON output shape while replacing any configured API key with the same prefix-truncated form already used by the non-JSON output (`${cfg.apiKey.slice(0, 8)}...`). This keeps both output modes consistent, lets users still recognize which key is loaded, and prevents disclosure of the full secret. When no API key is configured the field is omitted entirely (set to `undefined` so `JSON.stringify` drops it).

## Residual Risk

None

## Patch

```diff
diff --git a/packages/cli/src/commands/config/show.ts b/packages/cli/src/commands/config/show.ts
--- a/packages/cli/src/commands/config/show.ts
+++ b/packages/cli/src/commands/config/show.ts
@@ -11,7 +11,10 @@ export const configShowCommand = defineCommand({
     const cfg = resolveConfig(profile, apiKey);

     if (output === "json") {
-      logger.log(JSON.stringify(cfg, null, 2));
+      const redacted = cfg.apiKey
+        ? `${cfg.apiKey.slice(0, 8)}...`
+        : undefined;
+      logger.log(JSON.stringify({ ...cfg, apiKey: redacted }, null, 2));
       return;
     }
```