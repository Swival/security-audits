# Root Link Lockfile Entry Crashes Migration

## Classification

Denial of service, low severity. Confidence: certain.

## Affected Locations

`src/install/migration.rs:810`

## Summary

An attacker-controlled `package-lock.json` can mark the root package entry (`packages[""]`) as a link. During npm lockfile migration, Bun skips link entries while building the package list, then unconditionally indexes package slot zero for root setup. If the root entry is the only package, no package is appended and migration panics.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- Victim runs migration on a repository containing attacker-supplied `package-lock.json`.
- The lockfile uses `lockfileVersion` 2 or 3.
- The root `packages[""]` object contains a `link` property.

## Proof

Minimal triggering lockfile shape:

```json
{
  "lockfileVersion": 3,
  "packages": {
    "": {
      "link": true
    }
  }
}
```

Reachability is through `detect_and_load_other_lockfile`, which opens repository-local `package-lock.json` and calls `migrate_npm_lockfile`.

In the counting pass, `src/install/migration.rs` treats any package object with `link` as a link package, records `PACKAGE_ID_IS_LINK`, and continues without incrementing `package_idx`. For root path `""`, this leaves `package_idx == 0`.

In the package-building pass, the same link entry is skipped again, leaving `this.packages.len() == 0`.

Root setup then unconditionally performs:

```rust
this.packages.items_resolution_mut()[0] = Resolution::init(ResTagged::Root);
this.packages.items_meta_mut()[0].origin = lockfile::Origin::Local;
let root_name_hash = this.packages.items_name_hash()[0];
```

Those `[0]` accesses panic because no package zero exists.

## Why This Is A Real Bug

The lockfile is attacker-controlled repository data, and migration is a normal `bun install` path. The parser accepts the root object, then internal migration logic creates an impossible state: the root package is classified as a link and excluded, but later code assumes root package slot zero exists. This produces a deterministic crash from validly shaped JSON with a single malicious property.

## Fix Requirement

Reject a root `packages[""]` entry that contains `link`, or otherwise guarantee that package slot zero exists before root setup indexes it.

## Patch Rationale

The patch rejects `link` on the root package during the counting pass:

```diff
 if pkg.get(b"link").is_some() {
+    if pkg_path.is_empty() {
+        return Err(err!("InvalidNPMLockfile"));
+    }
     id_map.put_assume_capacity(
```

This is the earliest point where package path and `link` classification are both known. Returning `InvalidNPMLockfile` prevents the invalid root-link state from entering `id_map`, keeps the package count invariant intact, and converts the crash into a handled migration error.

## Residual Risk

None

## Patch

`047-root-link-lockfile-entry-crashes-migration.patch`

```diff
diff --git a/src/install/migration.rs b/src/install/migration.rs
index b3c65ffc63..e00a429bef 100644
--- a/src/install/migration.rs
+++ b/src/install/migration.rs
@@ -371,6 +371,9 @@ pub fn migrate_npm_lockfile<'a>(
         let pkg: &E::Object = pkg;
 
         if pkg.get(b"link").is_some() {
+            if pkg_path.is_empty() {
+                return Err(err!("InvalidNPMLockfile"));
+            }
             id_map.put_assume_capacity(
                 pkg_path,
                 IdMapValue {
```