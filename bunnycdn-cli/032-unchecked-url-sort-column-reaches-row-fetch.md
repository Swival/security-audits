# unchecked URL sort column reaches row fetch

## Classification

Validation gap, medium severity.

## Affected Locations

`packages/database-studio/client/src/components/TableView.tsx:65`

## Summary

`TableView` accepted the URL `sort` query parameter as a table column name and passed it to `fetchTableRows` without checking it against the fetched table schema. A crafted Studio URL could make the client request row data ordered by an invalid or unintended column expression, causing backend errors and UI load/refresh failure.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

An attacker can craft a database-studio URL containing a `sort` query parameter.

## Proof

The vulnerable code read `sortParam` from the URL and copied it into `sort.column`:

```ts
const sort = useMemo(() => {
  if (!sortParam) return undefined;
  return {
    column: sortParam,
    order: (orderParam === "desc" ? "desc" : "asc") as "asc" | "desc",
  };
}, [sortParam, orderParam]);
```

That `sort` object reached `fetchTableRows` during initial load, refresh, and pagination/page effects.

Reproduction confirmed:

- `?open=users&tab=users&sort=does_not_exist` caused a request like `/api/users?...&order=does_not_exist.asc`.
- The REST layer built `SELECT * FROM "users" ORDER BY "does_not_exist" ASC ...`.
- libsql returned `SQLITE_ERROR: no such column: does_not_exist`.
- The error was returned as a 500 and caused the Studio table load/refresh to fail.
- A crafted value such as `sort=name.asc,id&order=desc` was also propagated into backend ordering syntax as multiple order clauses: `ORDER BY "name" ASC, "id" DESC`.

Identifier quoting prevented direct SQL injection, but the unchecked value was still triggerable and affected backend row-fetch behavior.

## Why This Is A Real Bug

The client already fetches `schema.columns`, but the URL-controlled sort column was sent before validation. This allowed a URL parameter to select non-existent columns or manipulate REST ordering syntax, producing backend errors and denying normal table rendering for the crafted URL.

## Fix Requirement

Validate `sortParam` against the fetched `TableSchema.columns` before constructing or sending any sort object to `fetchTableRows`. If the URL sort value is absent or not an exact column-name match, omit sorting.

## Patch Rationale

The patch adds `getValidSort`, which returns a sort object only when:

- `sortParam` is present.
- A schema is available.
- `sortParam` exactly matches one of `schema.columns[*].name`.

The memoized `sort` now depends on `schema`, so subsequent row fetches, refreshes, and pagination only use schema-approved sort columns.

The initial load path was changed from parallel schema/data fetches to schema-first fetching. This ensures the first `fetchTableRows` call also validates the URL sort against the fetched schema before sending it.

## Residual Risk

None

## Patch

```diff
diff --git a/packages/database-studio/client/src/components/TableView.tsx b/packages/database-studio/client/src/components/TableView.tsx
index 34b9d8c..895f641 100644
--- a/packages/database-studio/client/src/components/TableView.tsx
+++ b/packages/database-studio/client/src/components/TableView.tsx
@@ -29,6 +29,20 @@ interface TableViewProps {
   onSelectTable: (name: string) => void;
 }
 
+function getValidSort(
+  s: TableSchema | null,
+  sortParam: string | null,
+  orderParam: string | null,
+) {
+  if (!sortParam || !s?.columns.some((column) => column.name === sortParam)) {
+    return undefined;
+  }
+  return {
+    column: sortParam,
+    order: (orderParam === "desc" ? "desc" : "asc") as "asc" | "desc",
+  };
+}
+
 export function TableView({ tableName, onSelectTable }: TableViewProps) {
   const [schema, setSchema] = useState<TableSchema | null>(null);
   const [data, setData] = useState<RowsResponse | null>(null);
@@ -59,13 +73,10 @@ export function TableView({ tableName, onSelectTable }: TableViewProps) {
     return [{ id: sortParam, desc: orderParam === "desc" }];
   }, [sortParam, orderParam]);
 
-  const sort = useMemo(() => {
-    if (!sortParam) return undefined;
-    return {
-      column: sortParam,
-      order: (orderParam === "desc" ? "desc" : "asc") as "asc" | "desc",
-    };
-  }, [sortParam, orderParam]);
+  const sort = useMemo(
+    () => getValidSort(schema, sortParam, orderParam),
+    [schema, sortParam, orderParam],
+  );
 
   const appliedFilters: FilterCondition[] = useMemo(() => {
     if (!filtersParam) return [];
@@ -91,17 +102,24 @@ export function TableView({ tableName, onSelectTable }: TableViewProps) {
     setError(null);
     setSchema(null);
     setData(null);
-    Promise.all([
-      fetchTableSchema(tableName),
-      fetchTableRows(tableName, 1, limit, [], sort, filterMode),
-    ])
+    fetchTableSchema(tableName)
+      .then((s) =>
+        fetchTableRows(
+          tableName,
+          1,
+          limit,
+          [],
+          getValidSort(s, sortParam, orderParam),
+          filterMode,
+        ).then((d) => [s, d] as const),
+      )
       .then(([s, d]) => {
         setSchema(s);
         setData(d);
       })
       .catch((e) => setError(e instanceof Error ? e.message : String(e)))
       .finally(() => setLoading(false));
-  }, [tableName, limit, filterMode, sort]);
+  }, [tableName, limit, filterMode, sortParam, orderParam]);
 
   useEffect(() => {
     setLoading(true);
```