# path traversal in saveView

## Classification

Medium severity path traversal vulnerability.

Confidence: certain.

## Affected Locations

`packages/database-shell/src/views.ts:34`

## Summary

`saveView` accepted an arbitrary `name` string and wrote to `join(viewsDir, name + ".sql")` without validating the name. A caller could pass traversal sequences such as `../x`, causing the write target to escape the intended views directory.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched.

## Preconditions

Caller passes an unvalidated view name containing path traversal.

## Proof

`saveView` receives `name` as a string parameter in `packages/database-shell/src/views.ts` and uses it directly:

```ts
export function saveView(viewsDir: string, name: string, sql: string): void {
  ensureDir(viewsDir);
  writeFileSync(join(viewsDir, name + VIEW_EXT), sql, "utf-8");
}
```

With:

```ts
saveView("/tmp/base/views", "../x", sql)
```

the target path becomes:

```text
/tmp/base/x.sql
```

because `join("/tmp/base/views", "../x.sql")` normalizes outside `viewsDir`.

`isValidViewName` already exists and restricts names to alphanumeric characters, hyphens, and underscores, but `saveView` did not call it. `saveView` is also re-exported from the public package API, so direct API callers could invoke it without the CLI validation path.

## Why This Is A Real Bug

The write operation is attacker-influenced through the exported `saveView` API. Path traversal in `name` changes the destination from the intended views directory to a parent or sibling path. This can create or overwrite `.sql` files outside the intended storage boundary wherever filesystem permissions allow.

CLI validation does not eliminate the bug because the vulnerable function is exported and callable directly.

## Fix Requirement

Validate `name` with `isValidViewName` before constructing the path or writing the file.

## Patch Rationale

The patch adds the same view-name validation used elsewhere before `join` and `writeFileSync` execute:

```ts
if (!isValidViewName(name)) throw new Error("Invalid view name");
```

This rejects traversal input such as `../x` because `/` and `.` are not permitted by `VIEW_NAME_RE`.

## Residual Risk

None

## Patch

```diff
diff --git a/packages/database-shell/src/views.ts b/packages/database-shell/src/views.ts
index 314a56d..8fb7afe 100644
--- a/packages/database-shell/src/views.ts
+++ b/packages/database-shell/src/views.ts
@@ -30,6 +30,7 @@ function ensureDir(viewsDir: string): void {
 
 /** Save a SQL query as a named view. */
 export function saveView(viewsDir: string, name: string, sql: string): void {
+  if (!isValidViewName(name)) throw new Error("Invalid view name");
   ensureDir(viewsDir);
   writeFileSync(join(viewsDir, name + VIEW_EXT), sql, "utf-8");
 }
```