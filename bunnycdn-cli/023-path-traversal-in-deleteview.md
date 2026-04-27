# Path Traversal In deleteView

## Classification

Medium severity vulnerability: path traversal leading to deletion of unintended `.sql` files.

Confidence: certain.

## Affected Locations

- `packages/database-shell/src/views.ts:46`
- Public reachability through `packages/database-shell/src/index.ts:26`
- Interactive reachability through `packages/database-shell/src/dot-commands.ts:462`

## Summary

`deleteView` accepted an untrusted view name and used it directly in `join(viewsDir, name + ".sql")`. A traversal name such as `../victim` resolves outside `viewsDir`; if the resulting file exists, `unlinkSync` deletes it.

The patch rejects invalid names before path construction by reusing the existing `isValidViewName` validator.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and confirmed against the supplied source and call paths.

## Preconditions

- A caller passes an untrusted `name` to `deleteView`.
- The process has filesystem permission to delete the resolved target file.
- The target path exists and ends with `.sql` after `name + VIEW_EXT` is applied.

## Proof

`packages/database-shell/src/views.ts` defined:

```ts
export function deleteView(viewsDir: string, name: string): boolean {
  const path = join(viewsDir, name + VIEW_EXT);
  if (!existsSync(path)) return false;
  unlinkSync(path);
  return true;
}
```

With `name = "../victim"` and `VIEW_EXT = ".sql"`, the computed path is equivalent to:

```text
<viewsDir>/../victim.sql
```

`existsSync` checks that resolved path, and `unlinkSync` deletes it if present.

The function is exported for direct package callers and is also reachable from the `.unsave` command, which passes user-controlled input to `deleteView`.

## Why This Is A Real Bug

The code already defines a restrictive view-name policy with `VIEW_NAME_RE = /^[a-zA-Z0-9_-]+$/`, but `deleteView` did not enforce it.

Other view operations are intended to operate on named views inside `viewsDir`. Without validation, `deleteView` can operate outside that directory, violating the intended filesystem boundary and allowing deletion of attacker-selected `.sql` files reachable through relative traversal.

## Fix Requirement

`deleteView` must reject names that are not valid view names before constructing the filesystem path.

The validation must block path separators, `..`, absolute paths, and any other character outside the intended alphanumeric, hyphen, and underscore set.

## Patch Rationale

The patch adds:

```ts
if (!isValidViewName(name)) return false;
```

before:

```ts
const path = join(viewsDir, name + VIEW_EXT);
```

This preserves existing behavior for valid view names while preventing traversal input from reaching `join`, `existsSync`, or `unlinkSync`.

Returning `false` is consistent with the function’s existing “not deleted” behavior.

## Residual Risk

None

## Patch

```diff
diff --git a/packages/database-shell/src/views.ts b/packages/database-shell/src/views.ts
index 314a56d..8102bf1 100644
--- a/packages/database-shell/src/views.ts
+++ b/packages/database-shell/src/views.ts
@@ -43,6 +43,7 @@ export function loadView(viewsDir: string, name: string): string | null {
 
 /** Delete a named view. Returns true if deleted, false if not found. */
 export function deleteView(viewsDir: string, name: string): boolean {
+  if (!isValidViewName(name)) return false;
   const path = join(viewsDir, name + VIEW_EXT);
   if (!existsSync(path)) return false;
   unlinkSync(path);
```