# npm tarball URL can receive registry authorization

## Classification

High severity information disclosure.

## Affected Locations

`src/install/PackageManager/PackageManagerEnqueue.rs:2174`

## Summary

A registry-controlled npm manifest tarball URL was downloaded with registry authorization enabled. If npm registry credentials were configured for the package scope, a malicious registry could set the package tarball URL to an attacker-controlled host and receive the package scope `Authorization` header on the initial tarball request.

## Provenance

Verified by Swival.dev Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- npm registry credentials are configured for the package scope.
- A malicious or compromised npm registry backend can return a manifest for that package scope.
- The manifest contains a tarball URL pointing to an attacker-controlled HTTP(S) origin.

## Proof

The reproduced path is:

- `get_or_put_resolved_package_with_find_result` handles a resolved npm manifest.
- In the `PreinstallState::Extract` branch, it uses `manifest.str(&find_result.package.tarball_url)` as the tarball download URL.
- That URL is registry-controlled via the npm manifest.
- The same call passed `Authorization::AllowAuthorization` to `generate_network_task_for_tarball`.
- `generate_network_task_for_tarball` selects credentials using `this.scope_for_package_name(pkg_name)`, i.e. the package registry scope, not the tarball URL origin.
- `NetworkTask::for_tarball` appends the scope `Authorization` header whenever `AllowAuthorization` is passed, and sends the request to the manifest-provided tarball URL.
- URL validation only required the tarball URL to start with `http://` or `https://`.

A cross-origin redirect safeguard exists in the HTTP client, but it does not mitigate this path because the first request is made directly to the manifest-specified tarball host with authorization already attached.

## Why This Is A Real Bug

The npm manifest is not a trusted source for deciding where registry credentials may be sent. The package registry origin and the tarball URL origin can differ. Passing `AllowAuthorization` unconditionally causes credentials scoped for the registry to be sent to any HTTP(S) tarball origin selected by the registry response, enabling credential disclosure to an attacker-controlled tarball host.

## Fix Requirement

Only permit authorization on npm tarball downloads when the tarball URL origin matches the trusted registry origin for the package scope. For all other tarball origins, use `Authorization::NoAuthorization`.

## Patch Rationale

The patch computes the manifest tarball URL once, parses its origin, and compares it with the configured scope registry origin:

```rust
let tarball_url = manifest.str(&find_result.package.tarball_url);
let authorization = if tarball_url.is_empty()
    || bun_url::URL::parse(tarball_url).origin
        == this
            .scope_for_package_name(this.lockfile.str(&name))
            .url
            .url()
            .origin
{
    crate::network_task::Authorization::AllowAuthorization
} else {
    crate::network_task::Authorization::NoAuthorization
};
```

The generated tarball task now receives `authorization` instead of unconditional `Authorization::AllowAuthorization`.

This preserves authorized downloads for tarballs served from the configured registry origin while preventing registry credentials from being sent to attacker-controlled or otherwise different origins.

## Residual Risk

None

## Patch

```diff
diff --git a/src/install/PackageManager/PackageManagerEnqueue.rs b/src/install/PackageManager/PackageManagerEnqueue.rs
index 54e7856b0a..5dcce11c5f 100644
--- a/src/install/PackageManager/PackageManagerEnqueue.rs
+++ b/src/install/PackageManager/PackageManagerEnqueue.rs
@@ -2167,6 +2167,20 @@ fn get_or_put_resolved_package_with_find_result(
             );
             debug_assert!(!this.network_dedupe_map.contains(&task_id));
 
+            let tarball_url = manifest.str(&find_result.package.tarball_url);
+            let authorization = if tarball_url.is_empty()
+                || bun_url::URL::parse(tarball_url).origin
+                    == this
+                        .scope_for_package_name(this.lockfile.str(&name))
+                        .url
+                        .url()
+                        .origin
+            {
+                crate::network_task::Authorization::AllowAuthorization
+            } else {
+                crate::network_task::Authorization::NoAuthorization
+            };
+
             break 'extract Some(ResolvedPackageResult {
                 package,
                 is_first_time: true,
@@ -2174,13 +2188,12 @@ fn get_or_put_resolved_package_with_find_result(
                     run_tasks::generate_network_task_for_tarball(
                         this,
                         task_id,
-                        manifest.str(&find_result.package.tarball_url),
+                        tarball_url,
                         behavior.is_required(),
                         dependency_id,
                         package,
                         name_and_version_hash,
-                        // its npm.
-                        crate::network_task::Authorization::AllowAuthorization,
+                        authorization,
                     )?
                     .expect("unreachable"),
                 )),
```