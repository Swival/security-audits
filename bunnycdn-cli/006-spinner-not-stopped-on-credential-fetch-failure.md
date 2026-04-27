# Spinner Not Stopped On Credential Fetch Failure

## Classification

Resource lifecycle bug, low severity, confidence certain.

## Affected Locations

`packages/cli/src/commands/db/studio.ts:78`

## Summary

`resolveCredentials()` starts an ora spinner before fetching missing database credentials, but only stops it after `Promise.all(fetches)` succeeds. If a database lookup or token generation request rejects, control skips `spin.stop()`, leaving the spinner active or stale while the error propagates.

## Provenance

Found by Swival Security Scanner: https://swival.dev

## Preconditions

- `db studio` is invoked without a complete URL/token pair.
- Credential resolution must call the API.
- `apiClient.GET(...)` or `apiClient.PUT(...)` rejects after `spin.start()`.

## Proof

`resolveCredentials()` starts the spinner with `spin.start()` in `packages/cli/src/commands/db/studio.ts`, then builds credential fetch promises. It awaits them with:

```ts
const [dbResult, tokenResult] = await Promise.all(fetches);

spin.stop();
```

If any promise rejects, JavaScript skips the following `spin.stop()` statement and propagates the rejection. The reproducer confirmed this path is reachable through API middleware errors from `packages/api/src/middleware.ts:111`, where non-OK responses throw `ApiError`.

## Why This Is A Real Bug

The spinner is an acquired UI resource with an explicit cleanup method. Cleanup is currently placed only on the success path. A rejection from credential lookup or token generation violates the resource lifecycle by leaving the spinner running or stale during error handling. In interactive TTY usage this can corrupt terminal output, and in non-immediate-exit call paths it leaks the spinner lifecycle.

## Fix Requirement

Wrap the `Promise.all(fetches)` await in `try/finally` and call `spin.stop()` from the `finally` block so cleanup runs on both success and failure.

## Patch Rationale

The patch preserves existing credential-fetch behavior and error propagation while guaranteeing spinner cleanup. `dbResult` and `tokenResult` are declared before the `try` block so successful results remain available after cleanup. Rejections still bubble to the caller unchanged.

## Residual Risk

None

## Patch

```diff
diff --git a/packages/cli/src/commands/db/studio.ts b/packages/cli/src/commands/db/studio.ts
index ee12f87..939047c 100644
--- a/packages/cli/src/commands/db/studio.ts
+++ b/packages/cli/src/commands/db/studio.ts
@@ -75,9 +75,13 @@ async function resolveCredentials(
     );
   }
 
-  const [dbResult, tokenResult] = await Promise.all(fetches);
-
-  spin.stop();
+  let dbResult: any;
+  let tokenResult: any;
+  try {
+    [dbResult, tokenResult] = await Promise.all(fetches);
+  } finally {
+    spin.stop();
+  }
 
   if (!url && dbResult) url = dbResult.data?.db?.url;
   if (!token && tokenResult) token = tokenResult.data?.token;
```