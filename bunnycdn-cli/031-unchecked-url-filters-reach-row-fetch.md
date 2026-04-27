# unchecked URL filters reach row fetch

## Classification

- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations

- `packages/database-studio/client/src/components/TableView.tsx:74`

## Summary

`TableView` parsed the `filters` URL parameter and returned any parsed JSON array as `FilterCondition[]` without validating the array elements. Because `appliedFilters` was passed into `fetchTableRows`, malformed URL-controlled filter entries could reach row-fetch request construction and, in some cases, backend SQL query construction or client-side exceptions.

## Provenance

- Source: Swival Security Scanner
- URL: https://swival.dev
- Finding was reproduced and patched from the scanner-reported location.

## Preconditions

- A user controls the `filters` URL parameter.

## Proof

At the vulnerable site, `filtersParam` was read from the URL, parsed with `JSON.parse`, and accepted if the parsed value was an array:

```ts
const parsed = JSON.parse(filtersParam);
return Array.isArray(parsed) ? parsed : [];
```

No validation ensured that each element had a valid `column`, `operator`, or `value`.

The resulting `appliedFilters` value flowed into row fetching:

- `fetchTableRows(tableName, page, limit, appliedFilters, sort, filterMode)`
- `fetchTableRows(tableName, page, limit, appliedFilters, sort, filterMode)` in `refresh`

A URL such as:

```text
?filters=[{}]
```

could make malformed filter objects reach row-fetch construction. Reproduction also confirmed backend impact:

- `packages/database-rest/src/parser.ts:162` treats any non-reserved query key as a filter column.
- `packages/database-rest/src/parser.ts:167` parses `undefined=eq.undefined` into `{ column: "undefined", operator: "eq", value: "undefined" }`.
- `packages/database-rest/src/sql.ts:21` quotes the identifier as `"undefined"`.
- `packages/database-rest/src/sql.ts:118` builds `SELECT * FROM "users" WHERE "undefined" = ? LIMIT 50 OFFSET 0`.

A URL such as:

```text
?filters=[null]
```

could instead trigger a client-side `TypeError` in `fetchTableRows`.

## Why This Is A Real Bug

The TypeScript cast to `FilterCondition[]` did not enforce runtime structure for URL-controlled JSON. Malformed arrays therefore violated the `FilterCondition` invariant and reached code that expected validated filter objects.

This did not appear to enable SQL injection because identifiers were quoted and values were parameterized. However, it could cause persistent failed table loads or client-side errors until the URL parameter was removed.

## Fix Requirement

Validate every URL-derived filter before use:

- The parsed value must be an array.
- Each filter must be a non-null object.
- `column` must be a string and must match an allowed schema column.
- `operator` must be a string and must be one of the supported filter operators.
- `value` must have the expected string shape.

## Patch Rationale

The patch adds an explicit `FILTER_OPERATORS` allowlist and changes `appliedFilters` parsing to reject invalid elements instead of trusting parsed JSON.

The patched logic now:

- Returns no URL filters until schema is available.
- Builds an allowlist from `schema.columns`.
- Accepts only object filters with a known column.
- Accepts only supported operators.
- Accepts only string values.
- Drops malformed entries before they can reach `fetchTableRows`.

This preserves valid URL filter behavior while preventing malformed URL-controlled data from crossing the client-side type boundary.

## Residual Risk

None

## Patch

```diff
diff --git a/packages/database-studio/client/src/components/TableView.tsx b/packages/database-studio/client/src/components/TableView.tsx
index 34b9d8c..1de15d1 100644
--- a/packages/database-studio/client/src/components/TableView.tsx
+++ b/packages/database-studio/client/src/components/TableView.tsx
@@ -29,6 +29,19 @@ interface TableViewProps {
   onSelectTable: (name: string) => void;
 }
 
+const FILTER_OPERATORS = new Set([
+  "=",
+  "!=",
+  ">",
+  "<",
+  ">=",
+  "<=",
+  "LIKE",
+  "NOT LIKE",
+  "IS NULL",
+  "IS NOT NULL",
+]);
+
 export function TableView({ tableName, onSelectTable }: TableViewProps) {
   const [schema, setSchema] = useState<TableSchema | null>(null);
   const [data, setData] = useState<RowsResponse | null>(null);
@@ -68,14 +81,25 @@ export function TableView({ tableName, onSelectTable }: TableViewProps) {
   }, [sortParam, orderParam]);
 
   const appliedFilters: FilterCondition[] = useMemo(() => {
-    if (!filtersParam) return [];
+    if (!filtersParam || !schema) return [];
+    const columns = new Set(schema.columns.map((column) => column.name));
     try {
       const parsed = JSON.parse(filtersParam);
-      return Array.isArray(parsed) ? parsed : [];
+      if (!Array.isArray(parsed)) return [];
+      return parsed.filter(
+        (filter): filter is FilterCondition =>
+          typeof filter === "object" &&
+          filter !== null &&
+          typeof filter.column === "string" &&
+          columns.has(filter.column) &&
+          typeof filter.operator === "string" &&
+          FILTER_OPERATORS.has(filter.operator) &&
+          typeof filter.value === "string",
+      );
     } catch {
       return [];
     }
-  }, [filtersParam]);
+  }, [filtersParam, schema]);
 
   // Sync filter row count from URL on table change
   useEffect(() => {
```