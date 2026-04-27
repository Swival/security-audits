# Generated Token Can Be Orphaned

## Classification

Error-handling bug, medium severity. Confidence: certain.

## Affected Locations

`packages/cli/src/commands/db/tokens/create.ts:185`

## Summary

`db tokens create` generated an auth token in parallel with a database-details GET using `Promise.all`. If token generation succeeded server-side but the GET failed, `Promise.all` rejected before the command printed or saved the token. The valid credential could therefore be created but lost to the user.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

## Preconditions

- `resolveDbId` succeeds.
- `PUT /v2/databases/{db_id}/auth/generate` succeeds and creates a token.
- `GET /v2/databases/{db_id}` fails or returns a non-OK response that is converted into a rejected promise.

## Proof

The original code started both requests unconditionally:

```ts
const [tokenResult, dbResult] = await Promise.all([
  client.PUT("/v2/databases/{db_id}/auth/generate", ...),
  client.GET("/v2/databases/{db_id}", ...),
]);
```

Because `Promise.all` rejects when either promise rejects, a failing database-details GET skipped:

- `spin.stop()`
- token extraction
- JSON output
- text output
- optional `.env` saving

The GET was unconditional for every invocation after `resolveDbId`, including `--output json`, where the database URL was not required.

## Why This Is A Real Bug

The generated token is the only secret returned to the caller. If the server creates it but a separate metadata request fails, the CLI never displays or persists the credential. The user cannot recover that exact token from command output and must generate another token or invalidate existing tokens.

The reproduced path is supported by API behavior: `authMiddleware` throws `ApiError` for non-OK responses, so the database-details GET can reject independently of successful token generation.

## Fix Requirement

Token generation must be handled first and treated as the authoritative operation. Database-details lookup must not prevent output or saving of an already-created token; GET failure should only mean optional metadata such as `dbUrl` is unavailable.

## Patch Rationale

The patch changes the flow to:

1. Await token generation directly.
2. Then request database details separately.
3. Swallow database-details GET failure by returning `undefined`.
4. Use optional chaining when reading `dbResult`.

This preserves failure behavior for token generation itself while making database metadata loss non-fatal.

## Residual Risk

None

## Patch

```diff
diff --git a/packages/cli/src/commands/db/tokens/create.ts b/packages/cli/src/commands/db/tokens/create.ts
index ff8fde1..6bee503 100644
--- a/packages/cli/src/commands/db/tokens/create.ts
+++ b/packages/cli/src/commands/db/tokens/create.ts
@@ -180,21 +180,20 @@ export const dbTokensCreateCommand = defineCommand<{
     const spin = spinner("Generating token...");
     spin.start();
 
-    // Fetch token and database details in parallel
-    const [tokenResult, dbResult] = await Promise.all([
-      client.PUT("/v2/databases/{db_id}/auth/generate", {
+    const tokenResult = await client.PUT("/v2/databases/{db_id}/auth/generate", {
+      params: { path: { db_id: databaseId } },
+      body: { authorization, expires_at: expiresAt },
+    });
+    const dbResult = await client
+      .GET("/v2/databases/{db_id}", {
         params: { path: { db_id: databaseId } },
-        body: { authorization, expires_at: expiresAt },
-      }),
-      client.GET("/v2/databases/{db_id}", {
-        params: { path: { db_id: databaseId } },
-      }),
-    ]);
+      })
+      .catch(() => undefined);
 
     spin.stop();
 
     const token = tokenResult.data?.token;
-    const dbUrl = dbResult.data?.db?.url;
+    const dbUrl = dbResult?.data?.db?.url;
 
     if (output === "json") {
       logger.log(
```