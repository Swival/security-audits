# Environment Value Echoed To Terminal

## Classification

Medium severity vulnerability: sensitive information disclosure through CLI output.

## Affected Locations

`packages/cli/src/commands/scripts/env/set.ts:202`

## Summary

The `scripts env set` command echoed non-secret environment variable values back to the terminal after a successful update. If a caller accidentally supplied a sensitive value without `--secret`, the value was written to stdout and could persist in terminal scrollback, shell logs, CI logs, or captured command output.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Caller uses `bunny scripts env set` with a sensitive value.
- Caller omits `--secret`.
- Output mode is not JSON.

## Proof

The value is populated from either the positional argument or prompt response:

- `packages/cli/src/commands/scripts/env/set.ts:125` assigns `rawValue` to `value`.
- `packages/cli/src/commands/scripts/env/set.ts:127` allows an interactive prompt response to populate `value`.

When `--secret` is omitted in non-interactive mode, `isSecret` defaults to `false`:

- `packages/cli/src/commands/scripts/env/set.ts:121`

The non-secret branch sends the same value in the API request body:

- `packages/cli/src/commands/scripts/env/set.ts:186`

After a successful PUT, non-JSON output reaches `logger.success`, which interpolates the raw value:

- `packages/cli/src/commands/scripts/env/set.ts:202`

`logger.success` writes to stdout through `console.log`, exposing the value in command output:

- `packages/cli/src/core/logger.ts:6`

## Why This Is A Real Bug

CLI output is commonly retained outside the process lifecycle, including terminal scrollback, shell session logging, CI logs, command transcripts, and redirected stdout. The affected command accepts arbitrary environment values, and users may mistakenly provide credentials, tokens, or other sensitive material without `--secret`. Echoing the raw value unnecessarily expands exposure after the API update succeeds.

This does not affect `--secret` values or `--output json`, but the stated preconditions are sufficient to trigger disclosure.

## Fix Requirement

Omit the environment value from success output. The command should confirm only that the named variable was set.

## Patch Rationale

The patch changes the non-secret success message from:

```ts
`Variable "${name}" set to "${value}".`
```

to:

```ts
`Variable "${name}" set successfully.`
```

This preserves useful confirmation while removing the sensitive data sink. The JSON output path remains unchanged and continues to emit only `{ name, secret }`.

## Residual Risk

None

## Patch

```diff
diff --git a/packages/cli/src/commands/scripts/env/set.ts b/packages/cli/src/commands/scripts/env/set.ts
index 07b58c0..6bb4d66 100644
--- a/packages/cli/src/commands/scripts/env/set.ts
+++ b/packages/cli/src/commands/scripts/env/set.ts
@@ -199,7 +199,7 @@ export const scriptsEnvSetCommand = defineCommand<SetArgs>({
     logger.success(
       isSecret
         ? `Secret "${name}" set successfully.`
-        : `Variable "${name}" set to "${value}".`,
+        : `Variable "${name}" set successfully.`,
     );
   },
 });
```