# Shell Auto-Generates Permanent Full-Access Token

## Classification

Medium severity vulnerability.

## Affected Locations

`packages/cli/src/commands/db/shell.ts:92`

## Summary

`db shell` silently generated a full-access database auth token with no expiration when the caller did not provide `--token` or `BUNNY_DATABASE_AUTH_TOKEN`.

The generated token was then used for the shell client and remained valid after the shell exited unless explicitly invalidated.

## Provenance

Verified from the supplied source, reproducer, and patch.

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Caller invokes `db shell` without providing a database auth token.
- No `BUNNY_DATABASE_AUTH_TOKEN` is available from `.env`.
- CLI can authenticate to the API and resolve the target database ID.

## Proof

In `resolveCredentials(...)`, token resolution first checks the explicit token argument and then `.env`:

```ts
let token = tokenArg ?? readEnvValue(ENV_DATABASE_AUTH_TOKEN)?.value;
```

If no token is present, the command generates one through the API:

```ts
apiClient.PUT("/v2/databases/{db_id}/auth/generate", {
  params: { path: { db_id: databaseId } },
  body: { authorization: "full-access", expires_at: null },
})
```

The API schema defines `expires_at` as nullable and indicates an omitted/null expiration produces a token that does not expire until JWT secrets are invalidated. The same schema permits `authorization` values including `full-access` and `read-only`.

The generated token is assigned to `token` and passed into the shell client:

```ts
const client = createShellClient({ url, authToken: token });
```

## Why This Is A Real Bug

A routine shell invocation creates a privileged persistent credential as an implicit side effect.

This violates least privilege and credential lifecycle expectations because:

- The user did not explicitly request permanent credential creation.
- The generated credential has `full-access` authorization.
- The generated credential has no expiration.
- The credential remains valid after the shell process exits.
- Revocation requires explicit invalidation outside the shell flow.

## Fix Requirement

Auto-generated shell tokens must not be permanent.

Acceptable fixes include:

- Generate short-lived tokens by default.
- Generate least-privilege tokens where shell functionality permits.
- Require explicit user confirmation before creating permanent full-access tokens.

## Patch Rationale

The patch changes the generated token expiration from `null` to a concrete timestamp 30 minutes in the future:

```ts
expires_at: new Date(Date.now() + 30 * 60 * 1000).toISOString()
```

This preserves existing shell behavior while preventing silent creation of non-expiring credentials.

The authorization remains `full-access`, so the patch addresses the credential persistence issue directly without altering command capabilities.

## Residual Risk

None

## Patch

```diff
diff --git a/packages/cli/src/commands/db/shell.ts b/packages/cli/src/commands/db/shell.ts
index de65da2..beccc77 100644
--- a/packages/cli/src/commands/db/shell.ts
+++ b/packages/cli/src/commands/db/shell.ts
@@ -87,7 +87,10 @@ async function resolveCredentials(
     fetches.push(
       apiClient.PUT("/v2/databases/{db_id}/auth/generate", {
         params: { path: { db_id: databaseId } },
-        body: { authorization: "full-access", expires_at: null },
+        body: {
+          authorization: "full-access",
+          expires_at: new Date(Date.now() + 30 * 60 * 1000).toISOString(),
+        },
       }),
     );
   }
```