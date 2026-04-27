# Patch Maps First Container To Wrong ID

## Classification

Data integrity bug, medium severity.

Confidence: certain.

## Affected Locations

- `packages/app-config/src/convert.ts:230`

## Summary

`configToPatchRequest` preserves container template IDs while converting app config into a PATCH request. The implementation incorrectly assigns `existingApp.containerTemplates[0].id` to the first configured container, regardless of the configured container name. When config container order differs from the existing application template order, the PATCH request can bind a container config to the wrong existing container identity.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

## Preconditions

- Patch config contains multiple containers.
- `config.app.containers` order differs from `existingApp.containerTemplates` order.
- The first configured container is not the same named container as `existingApp.containerTemplates[0]`.

## Proof

`configToPatchRequest` iterates configured containers from `Object.entries(config.app.containers)` and passes an existing template ID into `containerConfigToRequest`.

The buggy logic special-cases the first configured container:

```ts
const existing =
  i === 0
    ? existingApp.containerTemplates[0]
    : existingApp.containerTemplates.find((ct) => ct.name === name);
```

This means index `0` is matched by array position, not by container name.

Runtime reproduction against the committed implementation:

- Config order: `web`, `worker`
- Existing application order: `worker(id=ct-worker)`, `web(id=ct-web)`

Observed PATCH container templates:

```json
[
  { "id": "ct-worker", "name": "web", "...": "..." },
  { "id": "ct-worker", "name": "worker", "...": "..." }
]
```

The `web` config receives `ct-worker`, the `worker` config also receives `ct-worker`, and the real `web` ID `ct-web` is omitted.

## Why This Is A Real Bug

Container IDs are identity-bearing fields in PATCH requests. Preserving an ID for the wrong named container corrupts the mapping between user configuration and existing application state. The bug is reachable on every patch conversion and triggers solely from differing container order, without malformed input. The reproduced output shows both wrong identity attachment and duplicate IDs.

## Fix Requirement

Always preserve an existing container template ID by matching the existing template name to the configured container name. Do not use array index or first-template special-casing.

## Patch Rationale

The patch removes the index-based special case and performs name-based lookup for every configured container:

```ts
const existing = existingApp.containerTemplates.find((ct) => ct.name === name);
```

This makes ID preservation consistent for all containers and keeps the existing behavior for unmatched new containers, where `existing?.id` remains `undefined`.

## Residual Risk

None

## Patch

```diff
diff --git a/packages/app-config/src/convert.ts b/packages/app-config/src/convert.ts
index c5f197c..c2bab8e 100644
--- a/packages/app-config/src/convert.ts
+++ b/packages/app-config/src/convert.ts
@@ -224,12 +224,8 @@ export function configToPatchRequest(
 
   // Match containers by name to preserve existing IDs
   const entries = Object.entries(config.app.containers);
-  for (const [i, [name, c]] of entries.entries()) {
-    // First container matches first existing template (primary); rest match by name
-    const existing =
-      i === 0
-        ? existingApp.containerTemplates[0]
-        : existingApp.containerTemplates.find((ct) => ct.name === name);
+  for (const [name, c] of entries) {
+    const existing = existingApp.containerTemplates.find((ct) => ct.name === name);
     containers.push(containerConfigToRequest(name, c, existing?.id));
     collectVolumes(c, volumes, seenVolumes);
   }
```