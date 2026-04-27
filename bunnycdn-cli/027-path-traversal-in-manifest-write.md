# Path Traversal In Manifest Write

## Classification

Vulnerability: path traversal / arbitrary file write outside intended manifest directory.

Severity: medium.

Confidence: certain.

## Affected Locations

`packages/cli/src/core/manifest.ts:67`

## Summary

`saveManifestAt(root, filename, data)` writes to `join(root, ".bunny", filename)` without validating `filename`.

If a caller supplies `../outside.json`, Node path normalization resolves the target outside `.bunny`, allowing creation or overwrite of sibling files under `root`.

## Provenance

Verified from the supplied affected source, reproduced behavior, and patch.

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- A caller passes attacker-controlled `filename` to `saveManifestAt`.
- The chosen `root` is writable by the process.
- The attacker can choose traversal syntax such as `../outside.json`.

## Proof

Trigger:

```ts
saveManifestAt(root, "../outside.json", { pwned: true });
```

Propagation:

```ts
const dir = join(root, ".bunny");
writeFileSync(join(dir, filename), `${JSON.stringify(data, null, 2)}\n`, {
  mode: 0o600,
});
```

With `filename = "../outside.json"`, the write target becomes:

```text
join(root, ".bunny", "../outside.json") -> root/outside.json
```

Observed reproducer result:

```text
writeTarget=/tmp/.../bunny-manifest-poc-.../outside.json
outsideExists=true
insideExists=false
content={
  "pwned": true
}
```

## Why This Is A Real Bug

The helper is documented to save a manifest to `.bunny/<filename>`, but attacker-controlled traversal escapes that directory.

`mkdirSync(dir, { recursive: true })` only ensures `root/.bunny` exists; it does not constrain the subsequent `writeFileSync` path. `writeFileSync` creates or truncates the resolved target by default, so this can overwrite existing writable files outside `.bunny`.

The current internal CLI callers found use constants such as `script.json`, but the exported helper remains unsafe for any package caller that passes untrusted filenames.

## Fix Requirement

Reject manifest filenames that are not simple basename-style filenames.

Specifically reject:

- Absolute paths.
- Any `..` traversal component or substring.
- Any forward slash `/`.
- Any backslash `\`.

## Patch Rationale

The patch adds `assertManifestFilename(filename)` and calls it before writes in both manifest write helpers:

- `saveManifest`
- `saveManifestAt`

The validator rejects absolute paths, `..`, and path separators before any directory creation or file write occurs. This prevents `join(...)` from normalizing user input outside the intended `.bunny` directory.

Using `UserError` preserves project-style user-facing error handling.

## Residual Risk

None

## Patch

```diff
diff --git a/packages/cli/src/core/manifest.ts b/packages/cli/src/core/manifest.ts
index 956029b..05c2b26 100644
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
@@ -16,6 +16,12 @@ export interface ManifestData {
   scriptType?: number;
 }
 
+function assertManifestFilename(filename: string): void {
+  if (isAbsolute(filename) || filename.includes("..") || /[/\\]/.test(filename)) {
+    throw new UserError("Invalid manifest filename.");
+  }
+}
+
 /**
  * Walk up the directory tree looking for a `.bunny/<filename>` file.
  * Returns the project root (the directory containing `.bunny/`),
@@ -62,6 +68,7 @@ export function saveManifest<T extends object = ManifestData>(
   filename: string,
   data: T,
 ): void {
+  assertManifestFilename(filename);
   const dir = manifestDir(filename);
   mkdirSync(dir, { recursive: true });
   writeFileSync(join(dir, filename), `${JSON.stringify(data, null, 2)}\n`, {
@@ -83,6 +90,7 @@ export function saveManifestAt<T extends object = ManifestData>(
   filename: string,
   data: T,
 ): void {
+  assertManifestFilename(filename);
   const dir = join(root, MANIFEST_DIR);
   mkdirSync(dir, { recursive: true });
   writeFileSync(join(dir, filename), `${JSON.stringify(data, null, 2)}\n`, {
```