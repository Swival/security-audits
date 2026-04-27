# CSV escaping omits carriage returns

## Classification

Data integrity bug, medium severity.

## Affected Locations

`packages/database-shell/src/format.ts:72`

## Summary

CSV output incorrectly leaves fields containing a bare carriage return unquoted. A value such as `foo\rbar` contains no comma, quote, or line feed, so `csvEscape` returns it unchanged. CSV consumers may interpret the bare `\r` as a record separator, corrupting row boundaries and splitting one logical row into multiple parsed records.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

CSV output contains a value with carriage return but no comma, quote, or newline.

## Proof

In CSV mode, `printResultSet` sends each result cell through raw value formatting and then `csvEscape` before writing the joined row with `logger.log`.

The vulnerable escaping condition only checks for comma, double quote, and `\n`:

```ts
if (value.includes(",") || value.includes('"') || value.includes("\n")) {
  return `"${value.replace(/"/g, '""')}"`;
}
return value;
```

For an input cell `foo\rbar`, the condition is false and the emitted CSV contains a bare carriage return.

Confirmed practical effect with Python's standard `csv.reader`: parsing the CSV text `value\nfoo\rbar\n` yields three records:

```text
["value"]
["foo"]
["bar"]
```

The intended single data row value is split across record boundaries.

## Why This Is A Real Bug

CSV record separators include carriage-return based line endings in common parsers and CSV implementations. Because `printResultSet` emits query results directly in CSV mode, any database value containing a bare `\r` can alter the physical row structure of the output. This is not a display-only issue; downstream CSV importers, scripts, spreadsheets, and parsers can consume corrupted records.

## Fix Requirement

Quote CSV fields containing `\r`, in addition to fields containing comma, double quote, or `\n`.

## Patch Rationale

The patch extends the existing CSV quoting predicate with `value.includes("\r")`. This preserves the existing behavior for commas, quotes, and line feeds while ensuring carriage returns are enclosed in quoted fields. The existing quote-doubling logic remains correct for quoted CSV fields.

## Residual Risk

None

## Patch

```diff
diff --git a/packages/database-shell/src/format.ts b/packages/database-shell/src/format.ts
index 74e1e84..0eea954 100644
--- a/packages/database-shell/src/format.ts
+++ b/packages/database-shell/src/format.ts
@@ -69,7 +69,7 @@ export function formatValueRaw(val: unknown): string {
 
 /** Escape a value for CSV output (handles commas, quotes, newlines). */
 export function csvEscape(value: string): string {
-  if (value.includes(",") || value.includes('"') || value.includes("\n")) {
+  if (value.includes(",") || value.includes('"') || value.includes("\n") || value.includes("\r")) {
     return `"${value.replace(/"/g, '""')}"`;
   }
   return value;
```