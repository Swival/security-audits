# Deployment Key Printed In CLI Output

## Classification

Vulnerability: medium severity credential exposure.

Confidence: certain.

## Affected Locations

`packages/cli/src/commands/scripts/show.ts:93`

## Summary

The `scripts show` command printed an Edge Script deployment key in routine CLI output. The command fetched script details from `/compute/script/{id}`, passed `script.DeploymentKey` into `formatKeyValue` as `Deployment Key`, and emitted the formatted result through `logger.log`, which writes to stdout.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

## Preconditions

A user can run `scripts show` for an Edge Script that has a deployment key.

## Proof

The command fetches API data with `client.GET("/compute/script/{id}")` and stores the response as `script`.

For non-JSON output, `packages/cli/src/commands/scripts/show.ts:93` included:

```ts
{ key: "Deployment Key", value: script.DeploymentKey ?? "" },
```

That entry was passed to `formatKeyValue`, and the formatted output was printed by:

```ts
logger.log(...)
```

`logger.log` is implemented with `console.log`, so the deployment key was printed directly to stdout. This was reachable from the public `scripts show` command and exposed a deployment credential in default text output as well as table, CSV, and markdown output modes.

## Why This Is A Real Bug

A deployment key is a credential. Printing it by default in routine CLI output risks disclosure through terminal scrollback, logs, shell captures, CI output, support bundles, and copied command output. The exposure requires only normal use of `scripts show` against an Edge Script with a deployment key.

## Fix Requirement

Omit `DeploymentKey` from default human-readable output, or mask it unless the user explicitly requests credential disclosure.

## Patch Rationale

The patch removes the `Deployment Key` field from the formatted non-JSON output. This prevents accidental disclosure during routine `scripts show` usage while preserving other script metadata.

## Residual Risk

None

## Patch

```diff
diff --git a/packages/cli/src/commands/scripts/show.ts b/packages/cli/src/commands/scripts/show.ts
index 1478d24..321c298 100644
--- a/packages/cli/src/commands/scripts/show.ts
+++ b/packages/cli/src/commands/scripts/show.ts
@@ -90,7 +90,6 @@ export const scriptsShowCommand = defineCommand<ShowArgs>({
           },
           { key: "Default Hostname", value: script.DefaultHostname ?? "" },
           { key: "System Hostname", value: script.SystemHostname ?? "" },
-          { key: "Deployment Key", value: script.DeploymentKey ?? "" },
           {
             key: "Current Release",
             value: String(script.CurrentReleaseId ?? "—"),
```