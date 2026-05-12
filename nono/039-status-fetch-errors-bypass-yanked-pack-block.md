# status fetch errors bypass yanked-pack block

## Classification

Security control failure, medium severity.

Triggering the bypass requires the attacker to make the status request return an error rather than a yanked response. That generally means either a network-position advantage against the registry, or running offline (which is a common legitimate scenario). Failing closed eliminates the bypass at the cost of preventing launch when the registry is unreachable. The tradeoff is acceptable for the official-pack code path because the set of enforced targets is small and they represent the highest-value packs, but the impact is not as high as a remote bypass with no preconditions.

## Affected Locations

`crates/nono-cli/src/package_status.rs:77`

## Summary

Official pack yanked-status enforcement failed open when the status registry request returned an error. For active profiles depending on locked official packs, a registry-controlled fetch failure caused `enforce_official_pack_status` to return `Ok(())`, allowing launch without confirming whether the installed official pack was yanked.

## Provenance

Verified via reproduced finding from Swival.dev Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Active profile depends on a locked official pack.
- The official pack is one of the enforced targets, such as `always-further/claude` or `always-further/codex`.
- The package status request fails due to an HTTP error, malformed JSON, timeout, or equivalent `RegistryError`.

## Proof

`enforce_for_active_profile` calls `enforce_official_pack_status` for active profiles that depend on official packs.

In `crates/nono-cli/src/package_status.rs`, `enforce_official_pack_status` calls:

```rust
client.fetch_package_status(&package_ref, Some(locked.version.as_str()))
```

Before the patch, the `Err(error)` arm logged the failure and returned `Ok(())`:

```rust
Err(error) => {
    tracing::debug!(
        "could not check official pack status for {key}@{}: {error}",
        locked.version
    );
    return Ok(());
}
```

A successful status response with `installed_status == "yanked"` correctly returned `NonoError::ActionRequired`, which blocks launch. However, any status fetch error bypassed that decision path entirely.

Concrete trigger: an active profile depends on a locked official pack such as `always-further/claude`, and the registry endpoint `/api/v1/packages/always-further/claude/status?installed=<version>` fails. The launch proceeds because the yanked-status check fails open.

## Why This Is A Real Bug

The code implements a security-sensitive runtime block for yanked official packs. The block only works if the registry status check succeeds. Because registry fetch errors were treated as non-fatal, an attacker controlling or influencing the status registry could deterministically bypass the yanked-pack launch block by returning an error instead of a yanked response.

Local artifact verification does not mitigate this issue because it checks integrity/signatures and does not re-check yanked status.

## Fix Requirement

Status fetch errors for official packs must fail closed. If the client cannot verify the installed official pack status, launch must be blocked with `NonoError::ActionRequired`.

## Patch Rationale

The patch changes the `Err(error)` arm from allow-by-default to deny-by-default. It preserves the debug log, but returns `NonoError::ActionRequired` with the package key, locked version, and underlying error.

This makes yanked-status enforcement conservative: official packs launch only when status verification succeeds or when the returned status is explicitly acceptable.

## Residual Risk

None

## Patch

```diff
diff --git a/crates/nono-cli/src/package_status.rs b/crates/nono-cli/src/package_status.rs
index 964e09e..3c964df 100644
--- a/crates/nono-cli/src/package_status.rs
+++ b/crates/nono-cli/src/package_status.rs
@@ -74,7 +74,10 @@ fn enforce_official_pack_status(target: OfficialPackStatusTarget, silent: bool)
                 "could not check official pack status for {key}@{}: {error}",
                 locked.version
             );
-            return Ok(());
+            return Err(NonoError::ActionRequired(format!(
+                "could not verify official pack {key}@{} status: {error}",
+                locked.version
+            )));
         }
     };
```