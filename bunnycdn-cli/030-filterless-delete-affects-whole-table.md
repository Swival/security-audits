# Filterless Delete Affects Whole Table

## Classification

Data integrity bug, medium severity. Confidence: certain.

## Affected Locations

`packages/database-rest/src/sql.ts:177`

## Summary

`buildDeleteQuery(table, filters)` accepted an empty `filters` array and generated a `DELETE` statement without a `WHERE` clause. Calling `buildDeleteQuery("users", [])` produced:

```sql
DELETE FROM "users" RETURNING *
```

Executing that SQL deletes every row in the target table.

## Provenance

Verified from the provided source, reproducer summary, and patch.

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

Caller can invoke the exported SQL delete builder with an empty `FilterCondition[]`.

## Proof

`buildDeleteQuery` accepts `filters: FilterCondition[]` at `packages/database-rest/src/sql.ts:170`.

The function passes `filters` unchanged into `buildWhere(filters)` at `packages/database-rest/src/sql.ts:174`.

`buildWhere` returns an empty SQL fragment when `filters.length === 0` at `packages/database-rest/src/sql.ts:12`:

```ts
return { sql: "", args: [] };
```

As a result, `buildDeleteQuery("users", [])` constructs:

```sql
DELETE FROM "users" RETURNING *
```

with no `WHERE` clause and no bind arguments.

## Why This Is A Real Bug

A delete builder that silently emits an unqualified `DELETE` for an empty filter list violates the expected safety invariant for targeted deletes. The type signature allows the empty array, so callers can produce destructive whole-table SQL without an explicit opt-in.

The REST collection delete path separately rejects omitted or empty filters before calling the builder, so this is not reachable through `createRestHandler` for ordinary delete requests. The confirmed bug is narrower: the exported SQL builder itself permits filterless deletes.

## Fix Requirement

Reject empty delete filters by default, or require an explicit allow-all flag before generating a whole-table delete.

## Patch Rationale

The patch adds a guard at the start of `buildDeleteQuery`:

```ts
if (filters.length === 0) {
  throw new Error("Delete requires at least one filter");
}
```

This preserves existing behavior for filtered deletes while preventing accidental whole-table deletes through the exported builder. It also keeps `buildWhere` reusable for selects and counts, where an empty filter list is valid.

## Residual Risk

None

## Patch

```diff
diff --git a/packages/database-rest/src/sql.ts b/packages/database-rest/src/sql.ts
index 712bf3e..1f1bb0a 100644
--- a/packages/database-rest/src/sql.ts
+++ b/packages/database-rest/src/sql.ts
@@ -171,6 +171,10 @@ export function buildDeleteQuery(
   table: string,
   filters: FilterCondition[],
 ): SelectQuery {
+  if (filters.length === 0) {
+    throw new Error("Delete requires at least one filter");
+  }
+
   const where = buildWhere(filters);
 
   return {
```