# newline injection in pulled env file

## Classification

Data integrity bug, medium severity. Confidence: certain.

## Affected Locations

`packages/cli/src/commands/apps/env/pull.ts:76`

## Summary

`apps env pull` serialized API-provided environment variable names and values directly into `.env` line format. Because `.env` entries are line-delimited, any carriage return or newline in a pulled name or value created additional local `.env` lines, corrupting the pulled file and allowing injected variables to appear locally.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced from source inspection and a concrete payload showing that newline-containing values are written as extra `.env` entries.

## Preconditions

API returns an environment variable name or value containing `\r` or `\n`.

## Proof

Pulled variables originate from:

`client.GET("/apps/{appId}")`

The command reads:

`container.environmentVariables`

Before the patch, each entry was serialized as:

```ts
`${v.name}=${v.value ?? ""}`
```

Those serialized entries were joined with literal newlines and written directly to `.env`:

```ts
const envContent = `${vars.map((v) => `${v.name}=${v.value ?? ""}`).join("\n")}\n`;
writeFileSync(envPath, envContent, { mode: 0o600 });
```

A returned variable such as:

```json
{ "name": "SAFE", "value": "ok\nINJECTED=1" }
```

produced:

```env
SAFE=ok
INJECTED=1
```

`INJECTED=1` is then present as a separate local variable even though it was not a distinct pulled variable.

## Why This Is A Real Bug

The OpenAPI schema for `EnvironmentVariable` requires only a non-empty string `name` and string `value`; it does not exclude line breaks. The CLI therefore cannot assume the API response is safe for raw line-oriented `.env` serialization.

Because `.env` parsing treats newlines as record separators, raw newline characters alter file structure rather than remaining data inside a single value. This causes local configuration corruption and can introduce attacker-controlled variables into the generated `.env` file.

## Fix Requirement

Reject or safely encode environment variable names and values containing line breaks before writing `.env` content.

## Patch Rationale

The patch rejects both `\r` and `\n` in names and values before serialization:

```ts
for (const v of vars) {
  if (/\r|\n/.test(v.name) || /\r|\n/.test(v.value ?? "")) {
    throw new UserError("Environment variable names and values must not contain line breaks.");
  }
}
```

This prevents line-oriented `.env` corruption while preserving the existing simple `NAME=value` output format for valid variables. Rejection is appropriate because variable names with line breaks are invalid for practical `.env` use, and raw multiline values were not previously encoded in a parse-safe format.

## Residual Risk

None

## Patch

```diff
diff --git a/packages/cli/src/commands/apps/env/pull.ts b/packages/cli/src/commands/apps/env/pull.ts
index 9077652..ccb88f2 100644
--- a/packages/cli/src/commands/apps/env/pull.ts
+++ b/packages/cli/src/commands/apps/env/pull.ts
@@ -73,6 +73,12 @@ export const appsEnvPullCommand = defineCommand<PullArgs>({
       return;
     }
 
+    for (const v of vars) {
+      if (/\r|\n/.test(v.name) || /\r|\n/.test(v.value ?? "")) {
+        throw new UserError("Environment variable names and values must not contain line breaks.");
+      }
+    }
+
     const envContent = `${vars.map((v) => `${v.name}=${v.value ?? ""}`).join("\n")}\n`;
 
     const envPath = join(process.cwd(), ".env");
```