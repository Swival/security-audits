# Nonnumeric Offset Becomes NaN

## Classification

Validation gap, medium severity.

## Affected Locations

`packages/database-rest/src/parser.ts:157`

## Summary

A nonnumeric `offset` query parameter is parsed with `parseInt()` and assigned directly into `ParsedQuery.offset` without checking that the result is finite. For input such as `?offset=abc`, `parseInt("abc", 10)` returns `NaN`, which violates the `number` expectation and can propagate into generated SQL as `OFFSET NaN`.

## Provenance

Verified from supplied reproduction evidence and patch details.

Source: Swival Security Scanner, https://swival.dev

Confidence: certain.

## Preconditions

- Request URL contains a nonnumeric `offset` query parameter.
- The request is processed through the exported `parseQueryParams()` URL parser.

## Proof

Runtime evidence shows the malformed value reaches the parsed query object:

```text
parseQueryParams(new URL("http://localhost/users?offset=abc"))
=> { select: [], filters: [], order: [], limit: undefined, offset: NaN }
```

The parsed query then reaches SQL generation:

```text
buildSelectQuery("users", q).sql
=> SELECT * FROM "users" OFFSET NaN
```

With libsql/SQLite, equivalent SQL fails:

```text
SELECT * FROM users OFFSET NaN
=> SQLITE_ERROR: near "NaN": syntax error
```

The propagation path is:

- `packages/database-rest/src/parser.ts:157` parses `offset` with `parseInt(offsetParam, 10)`.
- `packages/database-rest/src/handler.ts:202` calls `parseQueryParams()`.
- `packages/database-rest/src/sql.ts:123` checks only `query.offset !== undefined`.
- `packages/database-rest/src/sql.ts:124` emits `OFFSET NaN`.
- `createRestHandler` catches the resulting database error and returns a 500 internal error.

## Why This Is A Real Bug

`ParsedQuery.offset` is typed as `number | undefined`, but the parser can produce `NaN`, which is a JavaScript `number` value but not a valid SQL offset. Because downstream SQL generation only checks for `undefined`, malformed client input can be converted into invalid SQL and cause a server-side database error instead of being rejected or safely omitted.

## Fix Requirement

Validate the parsed offset with `Number.isFinite()` before assigning it to `ParsedQuery.offset`. If the parsed value is not finite, the parser must reject it or omit it rather than preserving `NaN`.

## Patch Rationale

The patch introduces an intermediate `parsedOffset` value and assigns `offset` only when `Number.isFinite(parsedOffset)` is true:

```diff
-  const offset = offsetParam ? parseInt(offsetParam, 10) : undefined;
+  const parsedOffset = offsetParam ? parseInt(offsetParam, 10) : undefined;
+  const offset = Number.isFinite(parsedOffset) ? parsedOffset : undefined;
```

This prevents `NaN` from entering `ParsedQuery.offset`. For `?offset=abc`, `parsedOffset` becomes `NaN`, the finite check fails, and `offset` becomes `undefined`, preventing `OFFSET NaN` from being emitted.

## Residual Risk

None

## Patch

```diff
diff --git a/packages/database-rest/src/parser.ts b/packages/database-rest/src/parser.ts
index af7d2ff..c47042f 100644
--- a/packages/database-rest/src/parser.ts
+++ b/packages/database-rest/src/parser.ts
@@ -155,7 +155,8 @@ export function parseQueryParams(url: URL): ParsedQuery {
   const limit = limitParam ? parseInt(limitParam, 10) : undefined;
 
   const offsetParam = params.get("offset");
-  const offset = offsetParam ? parseInt(offsetParam, 10) : undefined;
+  const parsedOffset = offsetParam ? parseInt(offsetParam, 10) : undefined;
+  const offset = Number.isFinite(parsedOffset) ? parsedOffset : undefined;
 
   const filters: FilterCondition[] = [];
```