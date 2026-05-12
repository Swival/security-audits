# lockfile registry overrides official pack status authority

## Classification

security_control_failure, high severity, certain confidence

## Affected Locations

`crates/nono-cli/src/package_status.rs:67`

## Summary

Official pack yanked-status enforcement trusted the package lockfile registry value when selecting the status-check authority. Because the lockfile can be attacker-controlled or influenced by pull-time registry selection, an attacker could redirect official `always-further/claude` or `always-further/codex` status checks to an attacker registry and return a non-yanked status, allowing a yanked official pack to launch.

## Provenance

Verified by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- The active profile depends on `always-further/claude` or `always-further/codex`.
- The package lockfile contains the official pack and has `registry` set to an attacker-controlled registry.
- The trusted official registry would report the installed official pack version as `yanked`.

## Proof

`enforce_official_pack_status` reads the local lockfile, locates the official pack entry, then previously selected the registry URL from `lockfile.registry`:

```rust
let registry_url = if lockfile.registry.trim().is_empty() {
    resolve_registry_url(None)
} else {
    resolve_registry_url(Some(lockfile.registry.as_str()))
};
```

That URL is then used to construct the `RegistryClient` for `fetch_package_status`.

A practical bypass is:

1. Install or lock `always-further/claude` or `always-further/codex` with `lockfile.registry` pointing to an attacker registry.
2. Launch a profile that depends on that official pack.
3. Have the attacker registry return either `{"schema_version":1,"installed_status":"current"}` or omit `installed_status`.
4. The enforcement path treats the response as acceptable and returns `Ok(())` instead of blocking launch.

## Why This Is A Real Bug

The function implements security-sensitive official pack yanked-status enforcement, but it derived the authority for that enforcement from the same lockfile state being checked. This lets an attacker replace the authoritative status source for official packs.

The existing integrity checks do not close this gap. `verify_profile_packs` verifies installed files and stored Sigstore bundles, but it does not independently query the trusted official registry for current yanked status.

## Fix Requirement

Official pack status checks must always query the trusted official registry authority, regardless of the registry recorded in the lockfile.

## Patch Rationale

The patch replaces lockfile-derived registry selection with the default trusted registry resolution:

```rust
let registry_url = resolve_registry_url(None);
```

This keeps the lockfile package version as the subject of the status check while removing attacker control over the status authority. Official pack yanked-status enforcement now consistently queries the trusted official registry for `always-further/claude` and `always-further/codex`.

## Residual Risk

None

## Patch

```diff
diff --git a/crates/nono-cli/src/package_status.rs b/crates/nono-cli/src/package_status.rs
index 964e09e..24e87e4 100644
--- a/crates/nono-cli/src/package_status.rs
+++ b/crates/nono-cli/src/package_status.rs
@@ -61,11 +61,7 @@ fn enforce_official_pack_status(target: OfficialPackStatusTarget, silent: bool)
     };
 
     let package_ref = target.package_ref();
-    let registry_url = if lockfile.registry.trim().is_empty() {
-        resolve_registry_url(None)
-    } else {
-        resolve_registry_url(Some(lockfile.registry.as_str()))
-    };
+    let registry_url = resolve_registry_url(None);
     let client = RegistryClient::new(registry_url);
     let status = match client.fetch_package_status(&package_ref, Some(locked.version.as_str())) {
         Ok(status) => status,
```