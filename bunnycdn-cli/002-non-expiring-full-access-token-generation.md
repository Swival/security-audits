# Non-Expiring Full-Access Token Generation

## Classification

Vulnerability, medium severity.

## Affected Locations

`packages/cli/src/commands/db/quickstart.ts:246`

## Summary

Running `db quickstart` without `--token` caused the CLI to generate a database auth token with `authorization: "full-access"` and `expires_at: null`. The API schema defines null or omitted `expires_at` as non-expiring until JWT secrets are invalidated, so normal quickstart usage created a long-lived write-capable credential and printed it to the user.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- User runs `db quickstart` without providing `--token`.
- The command resolves a database ID and reaches the token-generation path.
- The API accepts `/v2/databases/{db_id}/auth/generate` with the provided body.

## Proof

In `packages/cli/src/commands/db/quickstart.ts`, `token` is initialized from `tokenArg`. When `--token` is absent, `token` remains undefined and the `!token` branch executes.

That branch calls:

```ts
client.PUT("/v2/databases/{db_id}/auth/generate", {
  params: { path: { db_id: databaseId } },
  body: { authorization: "full-access", expires_at: null },
});
```

The API schema for `expires_at` states that omitted or null expiration means the token will not expire until JWT secrets are invalidated. The generated token is then used as `tokenResult.data?.token` and is emitted in JSON output or printed as `BUNNY_DATABASE_AUTH_TOKEN=...` in the `.env` setup instructions when no existing token is present.

## Why This Is A Real Bug

This is reachable during ordinary quickstart usage, not an edge case or privileged debug path. A user who does not already have a token and does not pass `--token` receives a generated credential that has both broad database authorization and no natural expiry. If copied into application configuration, leaked from terminal output, captured by logs, or committed accidentally, the credential remains valid indefinitely unless JWT secrets are rotated or invalidated.

The behavior violates least privilege and secure-by-default expectations for a quickstart helper.

## Fix Requirement

Generated quickstart tokens must default to:

- Least-privilege authorization suitable for the quickstart use case.
- A finite expiration time.
- No non-expiring full-access credential unless explicitly requested through a deliberate privileged flow.

## Patch Rationale

The patch changes the generated token request from non-expiring full access to a read-only token expiring in 30 days:

```ts
body: {
  authorization: "read-only",
  expires_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
},
```

This reduces impact if the quickstart token is exposed and ensures the generated credential naturally ages out. It also aligns the default quickstart behavior with least privilege by avoiding write-capable access for generated credentials.

## Residual Risk

None

## Patch

```diff
diff --git a/packages/cli/src/commands/db/quickstart.ts b/packages/cli/src/commands/db/quickstart.ts
index 5442ed8..6bdb4d0 100644
--- a/packages/cli/src/commands/db/quickstart.ts
+++ b/packages/cli/src/commands/db/quickstart.ts
@@ -244,7 +244,10 @@ export const dbQuickstartCommand = defineCommand<{
         fetches.push(
           client.PUT("/v2/databases/{db_id}/auth/generate", {
             params: { path: { db_id: databaseId } },
-            body: { authorization: "full-access", expires_at: null },
+            body: {
+              authorization: "read-only",
+              expires_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
+            },
           }),
         );
       }
```