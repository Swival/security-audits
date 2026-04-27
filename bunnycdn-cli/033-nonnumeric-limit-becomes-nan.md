# Nonnumeric Limit Becomes NaN

## Classification

Validation gap, medium severity.

## Affected Locations

`packages/database-rest/src/parser.ts:154`

## Summary

A nonnumeric `limit` query parameter was parsed with `parseInt` and assigned directly to `ParsedQuery.limit`. For input such as `?limit=abc`, `parseInt("abc", 10)` returns `NaN`, which propagated into SQL generation as `LIMIT NaN` and caused a server-side database error path instead of treating the value as invalid or absent.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- A request URL includes a `limit` query parameter.
- The `limit` value is nonnumeric, for example `abc`.

## Proof

The request query reaches `parseQueryParams(url)` through `url.searchParams`.

In the vulnerable code, `params.get("limit")` was passed directly to `parseInt(limitParam, 10)`. For a value such as `abc`, JavaScript returns `NaN`, but the result was still assigned to `ParsedQuery.limit`.

The reproduced flow was:

- `GET /users?limit=abc` reaches `parseQueryParams(url)` from the collection handler.
- `parseInt("abc", 10)` produces `NaN`.
- `ParsedQuery.limit` becomes `NaN`.
- SQL generation checks only `query.limit !== undefined`, so `NaN` passes.
- The generated SQL becomes `SELECT * FROM "users" LIMIT NaN`.
- The malformed SQL reaches the database executor and is handled by the generic internal error path.

## Why This Is A Real Bug

`NaN` is a JavaScript `number` value, so it satisfies the TypeScript `limit?: number` shape but is not a valid SQL limit. The downstream SQL builder only distinguishes `undefined` from defined values, allowing `NaN` to be emitted into SQL.

This converts malformed client input into a server-side execution error instead of cleanly rejecting or omitting the invalid limit.

## Fix Requirement

Validate the parsed `limit` value with `Number.isFinite` before assigning it to `ParsedQuery.limit`. If the parsed value is not finite, reject it or omit it from the parsed query.

## Patch Rationale

The patch separates parsing from assignment:

```ts
const parsedLimit = limitParam ? parseInt(limitParam, 10) : undefined;
const limit = Number.isFinite(parsedLimit) ? parsedLimit : undefined;
```

This preserves existing behavior for valid numeric limits while preventing `NaN`, `Infinity`, or any other non-finite value from entering `ParsedQuery.limit`.

For `?limit=abc`, `parsedLimit` becomes `NaN`, `Number.isFinite(parsedLimit)` returns `false`, and `limit` is set to `undefined`. The SQL builder therefore does not emit a `LIMIT` clause.

## Residual Risk

None

## Patch

```diff
diff --git a/packages/database-rest/src/parser.ts b/packages/database-rest/src/parser.ts
index af7d2ff..f233203 100644
--- a/packages/database-rest/src/parser.ts
+++ b/packages/database-rest/src/parser.ts
@@ -152,7 +152,8 @@ export function parseQueryParams(url: URL): ParsedQuery {
   const order = parseOrder(params.get("order"));
 
   const limitParam = params.get("limit");
-  const limit = limitParam ? parseInt(limitParam, 10) : undefined;
+  const parsedLimit = limitParam ? parseInt(limitParam, 10) : undefined;
+  const limit = Number.isFinite(parsedLimit) ? parsedLimit : undefined;
 
   const offsetParam = params.get("offset");
   const offset = offsetParam ? parseInt(offsetParam, 10) : undefined;
```