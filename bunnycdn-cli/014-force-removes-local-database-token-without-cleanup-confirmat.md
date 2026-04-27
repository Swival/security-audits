# Force Delete Removes Local Database Token Without Cleanup Confirmation

## Classification

Logic error, medium severity.

## Affected Locations

`packages/cli/src/commands/db/delete.ts:166`

## Summary

`bunny db delete --force` skips not only the destructive database deletion confirmations, but also the later `.env` cleanup confirmation. When the local `.env` `BUNNY_DATABASE_URL` matches the deleted database URL, the command automatically removes `BUNNY_DATABASE_URL` and same-file `BUNNY_DATABASE_AUTH_TOKEN` without separately asking the user.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The user runs `db delete` with `--force`.
- The local `.env` contains `BUNNY_DATABASE_URL`.
- That `BUNNY_DATABASE_URL` exactly matches the deleted database’s `db.url`.
- The same `.env` file may also contain `BUNNY_DATABASE_AUTH_TOKEN`.

## Proof

- The `force` flag originates from CLI arguments and is passed to the destructive delete confirmation.
- When `force` is true, `confirm()` returns true immediately, so deletion prompts are skipped.
- After the API delete succeeds, non-JSON execution continues into local cleanup logic.
- The command reads `BUNNY_DATABASE_URL` from `.env` and compares it to `db.url`.
- If the values match, the cleanup confirmation also receives `{ force }`.
- Because `force` is reused, the cleanup prompt is auto-confirmed.
- `removeEnvValue()` then removes `BUNNY_DATABASE_URL`.
- If `BUNNY_DATABASE_AUTH_TOKEN` exists in the same `.env` file, it is also removed.

## Why This Is A Real Bug

`--force` is documented and implemented as a way to skip confirmations for database deletion. The later `.env` cleanup is a separate local file mutation with additional side effects, including removal of the database auth token. Reusing the deletion `force` flag for cleanup silently expands the scope of the user’s consent from “delete this remote database without prompts” to “also edit local credentials without prompts.”

This is reachable on every forced delete where the local `.env` URL matches the deleted database URL.

## Fix Requirement

Do not pass `force` to the `.env` cleanup confirmation. The cleanup prompt must remain interactive even when the database deletion itself was forced.

## Patch Rationale

The patch removes `{ force }` from the cleanup confirmation call:

```diff
const shouldClean = await confirm(
  `Remove ${ENV_DATABASE_URL} from ${envUrl.envPath}?`,
-  { force },
);
```

This preserves `--force` behavior for the destructive database deletion flow while requiring explicit confirmation before mutating local `.env` credentials.

## Residual Risk

None

## Patch

`014-force-removes-local-database-token-without-cleanup-confirmat.patch`

```diff
diff --git a/packages/cli/src/commands/db/delete.ts b/packages/cli/src/commands/db/delete.ts
index e895a80..19714a7 100644
--- a/packages/cli/src/commands/db/delete.ts
+++ b/packages/cli/src/commands/db/delete.ts
@@ -163,7 +163,6 @@ export const dbDeleteCommand = defineCommand<DeleteArgs>({
     if (envUrl && db.url && envUrl.value === db.url) {
       const shouldClean = await confirm(
         `Remove ${ENV_DATABASE_URL} from ${envUrl.envPath}?`,
-        { force },
       );
 
       if (shouldClean) {
```