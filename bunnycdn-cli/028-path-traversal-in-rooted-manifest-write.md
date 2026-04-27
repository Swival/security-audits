# Path Traversal In Rooted Manifest Write

## Classification

Vulnerability, medium severity.

Confidence: certain.

## Affected Locations

`packages/cli/src/core/manifest.ts:88`

## Summary

`saveManifestAt` accepted an arbitrary `filename` and wrote to `join(root, ".bunny", filename)` without constraining the filename to a single manifest basename. A caller-controlled value such as `../outside.json` escaped `root/.bunny` and wrote to `root/outside.json`; stronger traversal such as `../../escape.json` could escape the project root entirely.

The patch rejects absolute paths, path separators, and the `..` segment before constructing the output path.

## Provenance

Verified from supplied source, reproduced behavior, and patch evidence.

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- A caller controls or forwards the `filename` argument passed to exported `saveManifestAt`.
- The process has filesystem write permission to the resolved traversal target.

## Proof

`saveManifestAt` is exported and accepts `root`, `filename`, and `data`.

In the vulnerable implementation:

```ts
const dir = join(root, MANIFEST_DIR);
mkdirSync(dir, { recursive: true });
writeFileSync(join(dir, filename), `${JSON.stringify(data, null, 2)}\n`, {
  mode: 0o600,
});
```

`dir` is fixed to `<root>/.bunny`, but the final write target appends unvalidated `filename`.

A call equivalent to:

```ts
saveManifestAt(tmpRoot, "../outside.json", { pwned: true });
```

resolves the write target to:

```text
<tmpRoot>/outside.json
```

not:

```text
<tmpRoot>/.bunny/outside.json
```

The reproducer confirmed that this created `<tmpRoot>/outside.json` containing the supplied JSON payload.

## Why This Is A Real Bug

The function name and documentation promise a write to `.bunny/<filename>` within a specific root directory. The implementation allowed path traversal out of `.bunny` and, with additional `../` segments, out of the root itself.

Although current in-tree CLI call sites use the constant `SCRIPT_MANIFEST`, `saveManifestAt` is exported and reachable to callers using rooted manifest writes. Under the stated precondition, untrusted filename input can overwrite attacker-selected relative paths writable by the process.

## Fix Requirement

Reject any `filename` that is not a plain manifest filename.

Required constraints:

- Reject absolute paths.
- Reject values containing `/`.
- Reject values containing `\`.
- Reject `..` path segments.

## Patch Rationale

The patch imports `isAbsolute` from `node:path` and validates `filename` before creating the manifest directory or writing the file:

```ts
if (
  isAbsolute(filename) ||
  filename === ".." ||
  filename.includes("/") ||
  filename.includes("\\")
) {
  throw new UserError("Manifest filename must not contain path segments.");
}
```

This prevents traversal payloads such as `../outside.json`, `../../escape.json`, Windows-style separator payloads, and absolute path writes. Because both forward slash and backslash are rejected, the filename is constrained to a single path component before `join(dir, filename)` is evaluated.

## Residual Risk

None

## Patch

```diff
diff --git a/packages/cli/src/core/manifest.ts b/packages/cli/src/core/manifest.ts
index 956029b..93ad671 100644
--- a/packages/cli/src/core/manifest.ts
+++ b/packages/cli/src/core/manifest.ts
@@ -5,7 +5,7 @@ import {
   unlinkSync,
   writeFileSync,
 } from "node:fs";
-import { dirname, join, resolve } from "node:path";
+import { dirname, isAbsolute, join, resolve } from "node:path";
 import { UserError } from "./errors.ts";
 
 const MANIFEST_DIR = ".bunny";
@@ -83,6 +83,15 @@ export function saveManifestAt<T extends object = ManifestData>(
   filename: string,
   data: T,
 ): void {
+  if (
+    isAbsolute(filename) ||
+    filename === ".." ||
+    filename.includes("/") ||
+    filename.includes("\\")
+  ) {
+    throw new UserError("Manifest filename must not contain path segments.");
+  }
+
   const dir = join(root, MANIFEST_DIR);
   mkdirSync(dir, { recursive: true });
   writeFileSync(join(dir, filename), `${JSON.stringify(data, null, 2)}\n`, {
```