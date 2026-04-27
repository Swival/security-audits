# Unescaped Environment Value Injection

## Classification

Vulnerability, medium severity.

## Affected Locations

`packages/cli/src/commands/scripts/env/pull.ts:130`

## Summary

`bunny scripts env pull` serialized remote EdgeScript variable names and values directly into `.bunny/.env` as raw `NAME=VALUE` lines. If the API returned a variable value containing a newline followed by `NAME=VALUE` text, the generated dotenv file contained an attacker-controlled extra environment entry.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The API returns an EdgeScript variable value containing a newline and `NAME=VALUE` text.
- The user runs `bunny scripts env pull`.
- The command writes `.bunny/.env`.

## Proof

The command fetches `/compute/script/{id}` and assigns `script?.EdgeScriptVariables ?? []` without validation.

Each variable was serialized directly:

```ts
`${v.Name ?? ""}=${v.DefaultValue ?? ""}`
```

The serialized lines were joined with newline separators and written to `.bunny/.env`:

```ts
.join("\n")
writeFileSync(envPath, content, { mode: 0o600 })
```

A single API variable such as:

```env
Name=SAFE
DefaultValue=ok
INJECTED=value
```

produced a generated dotenv artifact equivalent to:

```env
SAFE=ok
INJECTED=value
```

Thus one remote variable persisted two dotenv entries.

## Why This Is A Real Bug

The command explicitly creates a local `.env` file, a format interpreted line-by-line by dotenv tooling. Because raw values were written without quoting or newline escaping, embedded newlines became real record separators. This allows a single remote value to alter the structure of the generated environment file and introduce additional assignments.

The reproduced impact is injection into `.bunny/.env` and any user or tooling flow that reads that file as dotenv.

## Fix Requirement

- Serialize dotenv values with quoting and escaping.
- Escape backslashes, quotes, line feeds, and carriage returns in values.
- Reject variable names containing newline characters so names cannot create additional records.

## Patch Rationale

The patch adds `serializeEnvVariable`, which:

- Reads the variable name and rejects `\r` or `\n` using `UserError`.
- Escapes `\`, `"`, `\n`, and `\r` in values.
- Emits each entry as `NAME="escaped value"`.
- Replaces the raw template serialization with `variables.map(serializeEnvVariable).join("\n")`.

This preserves a one-variable-to-one-line invariant for generated `.env` output.

## Residual Risk

None

## Patch

```diff
diff --git a/packages/cli/src/commands/scripts/env/pull.ts b/packages/cli/src/commands/scripts/env/pull.ts
index 721a9c1..2074bee 100644
--- a/packages/cli/src/commands/scripts/env/pull.ts
+++ b/packages/cli/src/commands/scripts/env/pull.ts
@@ -5,6 +5,7 @@ import type { components } from "@bunny.net/api/generated/compute.d.ts";
 import { resolveConfig } from "../../../config/index.ts";
 import { clientOptions } from "../../../core/client-options.ts";
 import { defineCommand } from "../../../core/define-command.ts";
+import { UserError } from "../../../core/errors.ts";
 import { logger } from "../../../core/logger.ts";
 import { manifestDir, resolveManifestId } from "../../../core/manifest.ts";
 import { confirm, spinner } from "../../../core/ui.ts";
@@ -26,6 +27,23 @@ interface PullArgs {
   [ARG_FORCE]?: boolean;
 }
 
+function serializeEnvVariable(variable: EdgeScriptVariable): string {
+  const name = variable.Name ?? "";
+  if (/[\r\n]/.test(name)) {
+    throw new UserError(
+      `Invalid environment variable name: ${JSON.stringify(name)}`,
+    );
+  }
+
+  const value = (variable.DefaultValue ?? "")
+    .replace(/\\/g, "\\\\")
+    .replace(/"/g, '\\"')
+    .replace(/\n/g, "\\n")
+    .replace(/\r/g, "\\r");
+
+  return `${name}="${value}"`;
+}
+
 /**
  * Pull environment variables from an Edge Script to a local `.bunny/.env` file.
  *
@@ -125,9 +143,7 @@ export const scriptsEnvPullCommand = defineCommand<PullArgs>({
       }
     }
 
-    const content = `${variables
-      .map((v: EdgeScriptVariable) => `${v.Name ?? ""}=${v.DefaultValue ?? ""}`)
-      .join("\n")}\n`;
+    const content = `${variables.map(serializeEnvVariable).join("\n")}\n`;
 
     mkdirSync(dir, { recursive: true });
     writeFileSync(envPath, content, { mode: 0o600 });
```