# Path Traversal In loadView

## Classification

Vulnerability: path traversal

Severity: medium

Confidence: certain

## Affected Locations

- `packages/database-shell/src/views.ts:39`

## Summary

`loadView` accepted an arbitrary `name`, appended `.sql`, and passed it to `join(viewsDir, name + ".sql")` without validating the name. Because `join` normalizes `../` path segments, a caller could escape `viewsDir` and read SQL files from adjacent or parent directories. The loaded SQL could then be executed by the database shell `.view` command.

## Provenance

Detected by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched from the verified report.

## Preconditions

- A caller passes an untrusted `name` to `loadView`.
- A `.sql` file exists at the attacker-controlled escaped path.
- The loaded view content is subsequently executed, as in the `.view` command path.

## Proof

`loadView` constructed the file path directly from the supplied name:

```ts
const path = join(viewsDir, name + VIEW_EXT);
```

For a name such as `../outside/evil`, this becomes an escaped normalized path outside the intended views directory. `existsSync(path)` then checks that escaped path, and `readFileSync(path, "utf-8")` reads it if present.

Runtime reproduction confirmed that invoking:

```text
.view ../outside/evil
```

with an adjacent `outside/evil.sql` containing:

```sql
SELECT 123;
```

loaded the file outside `viewsDir` and passed `SELECT 123;` to the mock database client for execution.

## Why This Is A Real Bug

The code already defines `isValidViewName` with the intended constraint:

```ts
/^[a-zA-Z0-9_-]+$/
```

but `loadView` did not enforce it. As a result, path separators and traversal segments were accepted. The vulnerable path is reachable because the `.view` command parses the name and calls `loadView(state.viewsDir, name)` without validating the view name first. The returned SQL is split and sent to `client.execute`, turning an arbitrary file read within `.sql` suffix constraints into SQL execution through the shell.

## Fix Requirement

Validate `name` with `isValidViewName` before constructing the filesystem path in `loadView`.

Invalid names must not be joined with `viewsDir`, checked with `existsSync`, or read with `readFileSync`.

## Patch Rationale

The patch adds an early validation guard:

```ts
if (!isValidViewName(name)) return null;
```

This rejects traversal payloads such as `../outside/evil` because `/` and `.` are not allowed by `VIEW_NAME_RE`. Returning `null` preserves the existing “view not found” behavior for callers while preventing path construction for invalid names.

## Residual Risk

None

## Patch

```diff
diff --git a/packages/database-shell/src/views.ts b/packages/database-shell/src/views.ts
index 314a56d..f809943 100644
--- a/packages/database-shell/src/views.ts
+++ b/packages/database-shell/src/views.ts
@@ -36,6 +36,7 @@ export function saveView(viewsDir: string, name: string, sql: string): void {
 
 /** Load a named view and return its SQL, or null if it doesn't exist. */
 export function loadView(viewsDir: string, name: string): string | null {
+  if (!isValidViewName(name)) return null;
   const path = join(viewsDir, name + VIEW_EXT);
   if (!existsSync(path)) return null;
   return readFileSync(path, "utf-8").trim();
```