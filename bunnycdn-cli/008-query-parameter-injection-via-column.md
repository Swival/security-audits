# Query Parameter Injection via Column

## Classification

Medium severity vulnerability.

## Affected Locations

`packages/database-studio/client/src/api.ts:142`

## Summary

`fetchRowLookup` constructed a REST API URL by concatenating the caller-controlled `column` argument directly into the query string. Because `column` was not encoded or validated, a value containing query delimiters such as `&` or `#` could alter the outgoing request semantics.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

A caller controls the `fetchRowLookup` `column` argument.

## Proof

The vulnerable URL construction was:

```ts
`${BASE}/api/${encodeURIComponent(table)}?${column}=eq.${encodeURIComponent(value)}&limit=1`
```

Only `table` and `value` were encoded. `column` was concatenated raw immediately after `?`.

A malicious column such as:

```text
id=eq.1&limit=100#=eq.ignored
```

produces a URL equivalent to:

```text
/api/<table>?id=eq.1&limit=100#=eq.ignored=eq.<value>&limit=1
```

URL parsing exposes only the parameters before the fragment:

```text
id=eq.1
limit=100
```

The intended lookup value and trailing `limit=1` are bypassed. The server then parses and applies injected REST parameters: `packages/database-rest/src/parser.ts:148`, `packages/database-rest/src/parser.ts:154`, and `packages/database-rest/src/sql.ts:120`.

## Why This Is A Real Bug

The helper accepts `column` as an argument and exports it for reuse. When invoked with a non-validated column name, query syntax characters in `column` are interpreted as URL structure instead of as a query parameter key. This allows the caller to inject accepted REST parameters such as filters, `select`, `order`, `limit`, or `offset`, changing the lookup semantics.

The current built-in Studio UI path may be limited because `fetchTableSchema` currently returns `foreignKeys: []`, but the vulnerable exported helper remains exploitable under the stated precondition.

## Fix Requirement

The column name must not be interpolated into the query string raw. It must be encoded as a query parameter key or validated against known schema column names before request construction.

## Patch Rationale

The patch encodes `column` with `encodeURIComponent` before inserting it into the query string:

```ts
`${BASE}/api/${encodeURIComponent(table)}?${encodeURIComponent(column)}=eq.${encodeURIComponent(value)}&limit=1`
```

This causes characters such as `&`, `=`, and `#` to be transmitted as part of the parameter name rather than interpreted as query delimiters or fragment markers. The existing behavior for valid column names is preserved.

## Residual Risk

None

## Patch

```diff
diff --git a/packages/database-studio/client/src/api.ts b/packages/database-studio/client/src/api.ts
index f4bb684..bd21ecd 100644
--- a/packages/database-studio/client/src/api.ts
+++ b/packages/database-studio/client/src/api.ts
@@ -140,7 +140,7 @@ export const fetchRowLookup = async (
   value: string,
 ): Promise<RowLookupResponse> => {
   const res = await fetch(
-    `${BASE}/api/${encodeURIComponent(table)}?${column}=eq.${encodeURIComponent(value)}&limit=1`,
+    `${BASE}/api/${encodeURIComponent(table)}?${encodeURIComponent(column)}=eq.${encodeURIComponent(value)}&limit=1`,
   );
   if (!res.ok) throw new Error(`Lookup failed: ${res.status}`);
   const body = await res.json();
```