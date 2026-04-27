# CSV Formula Prefixes Preserved

## Classification

Medium severity vulnerability: CSV/spreadsheet formula injection.

## Affected Locations

`packages/cli/src/core/format.ts:49`

## Summary

CSV output preserved cells beginning with formula-trigger characters (`=`, `+`, `-`, `@`). When attacker-controlled values were exported with `--output csv` and opened in spreadsheet software, those cells could be interpreted as formulas.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- An attacker-controlled cell value is included in CLI tabular output.
- The user selects CSV output, for example with `--output csv`.
- The resulting CSV is opened in spreadsheet software that evaluates formula-leading cells.

## Proof

`packages/cli/src/core/format.ts` routes CSV output through `formatTable(..., "csv")`, which maps headers and row cells through `csvEscape`.

Before the patch, `csvEscape` only quoted values containing commas, double quotes, or newlines:

```ts
if (value.includes(",") || value.includes('"') || value.includes("\n")) {
  return `"${value.replace(/"/g, '""')}"`;
}
return value;
```

A formula-leading value without those quoting triggers was returned unchanged.

Runtime reproduction against committed code showed:

```text
csvEscape("=1+1") => "=1+1"
formatTable(["Name","Value"], [["SAFE","=2+2"]], "csv") =>
Name,Value
SAFE,=2+2
```

A practical propagation path exists through environment variable listing:

- `packages/cli/src/cli.ts:56` exposes `--output csv`.
- `packages/cli/src/commands/apps/env/list.ts:74` maps remote environment variable values into rows.
- `packages/cli/src/commands/apps/env/list.ts:76` exports those rows through `formatTable(..., output)`.

## Why This Is A Real Bug

CSV is often consumed by spreadsheet applications. Many spreadsheet programs treat unescaped cells beginning with `=`, `+`, `-`, or `@` as formulas. Because attacker-controlled row values reached CSV output unchanged, a malicious value such as `=2+2` could be interpreted as spreadsheet formula content instead of inert text.

## Fix Requirement

CSV cell values beginning with `=`, `+`, `-`, or `@` must be neutralized before CSV escaping. The neutralization must occur before quoting so that quoted CSV fields are also protected when imported by spreadsheet software.

## Patch Rationale

The patch prefixes formula-leading values with an apostrophe before normal CSV escaping:

```ts
const safeValue = /^[=+\-@]/.test(value) ? `'${value}` : value;
```

It then applies the existing CSV quote escaping logic to `safeValue`, preserving RFC-style escaping for commas, quotes, and newlines while preventing spreadsheet formula interpretation.

## Residual Risk

None

## Patch

```diff
diff --git a/packages/cli/src/core/format.ts b/packages/cli/src/core/format.ts
index 395ad8a..1e2ef75 100644
--- a/packages/cli/src/core/format.ts
+++ b/packages/cli/src/core/format.ts
@@ -43,10 +43,11 @@ export function formatDateTime(
 
 /** Escape a value for CSV output. */
 export function csvEscape(value: string): string {
-  if (value.includes(",") || value.includes('"') || value.includes("\n")) {
-    return `"${value.replace(/"/g, '""')}"`;
+  const safeValue = /^[=+\-@]/.test(value) ? `'${value}` : value;
+  if (safeValue.includes(",") || safeValue.includes('"') || safeValue.includes("\n")) {
+    return `"${safeValue.replace(/"/g, '""')}"`;
   }
-  return value;
+  return safeValue;
 }
 
 /** Escape pipe characters for markdown table cells. */
```