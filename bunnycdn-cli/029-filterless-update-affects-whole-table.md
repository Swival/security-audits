# Filterless Update Affects Whole Table

## Classification

Data integrity bug, medium severity.

## Affected Locations

`packages/database-rest/src/sql.ts:165`

## Summary

`buildUpdateQuery` accepted an empty `filters` array and passed it unchanged to `buildWhere`. Because `buildWhere([])` returns an empty SQL fragment, the generated `UPDATE` statement omitted `WHERE` and affected every row in the target table.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

A caller can invoke exported `buildUpdateQuery` with an empty `filters` array.

## Proof

`buildUpdateQuery("users", { age: 99 }, [])` generated:

```text
UPDATE "users" SET "age" = ? RETURNING *
```

Runtime confirmation against an in-memory SQLite table showed all rows were updated:

```text
[{"id":1,"age":99},{"id":2,"age":99},{"id":3,"age":99}]
[{"id":1,"age":99},{"id":2,"age":99},{"id":3,"age":99}]
```

The reachable path is local/direct package usage: `packages/database-rest/src/index.ts:23` exports `buildUpdateQuery`. The collection HTTP `PATCH /:table` path in `packages/database-rest/src/handler.ts:278` already prevents this, so the verified impact is limited to direct callers of the exported query builder.

## Why This Is A Real Bug

An update helper normally preserves caller intent by constraining mutation to the supplied filter set. Here, an omitted filter silently changed semantics from targeted update to full-table update. The generated SQL was valid and executable, so the failure mode was not a rejected request but a destructive broad mutation.

## Fix Requirement

Reject empty filters for updates unless an explicit, intentional allow-all mechanism is introduced.

## Patch Rationale

The patch adds an early guard in `buildUpdateQuery`:

```ts
if (filters.length === 0) {
  throw new Error("Update requires at least one filter");
}
```

This prevents construction of filterless `UPDATE` SQL while preserving existing behavior for filtered updates. The guard is placed before SQL assembly so unsafe statements are rejected before they can be returned to callers.

## Residual Risk

None

## Patch

```diff
diff --git a/packages/database-rest/src/sql.ts b/packages/database-rest/src/sql.ts
index 712bf3e..9c96413 100644
--- a/packages/database-rest/src/sql.ts
+++ b/packages/database-rest/src/sql.ts
@@ -155,6 +155,10 @@ export function buildUpdateQuery(
   values: Record<string, unknown>,
   filters: FilterCondition[],
 ): SelectQuery {
+  if (filters.length === 0) {
+    throw new Error("Update requires at least one filter");
+  }
+
   const setClauses = Object.keys(values).map(
     (col) => `${quoteIdentifier(col)} = ?`,
   );
```