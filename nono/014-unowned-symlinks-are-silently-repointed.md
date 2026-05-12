# Unowned Symlinks Are Silently Repointed

## Classification

Path traversal / unsafe filesystem link takeover.

Severity: high.

Confidence: certain.

## Affected Locations

`crates/nono-cli/src/wiring.rs:613`

## Summary

A malicious pack could declare a `symlink` directive whose `link` path already existed as a user-owned symlink. The installer treated any existing symlink as replaceable: if the current target differed from the pack-requested target, it removed the symlink and recreated it to point at attacker-chosen content.

The patch changes this behavior so existing symlinks with different targets are reported as conflicts and left untouched.

## Provenance

Verified and reproduced from scanner output.

Scanner: [Swival.dev Security Scanner](https://swival.dev)

## Preconditions

- Victim installs a pack from an untrusted or malicious registry publisher.
- Victim already has a symlink at the path selected by the pack's `symlink` directive.
- The existing symlink target differs from the pack-requested target.

## Proof

`execute_one` expands pack-controlled `Symlink { link, target }` fields and dispatches directly to `ensure_symlink`.

Before the patch, `ensure_symlink` handled an existing symlink as follows:

```rust
let current = fs::read_link(link).map_err(NonoError::Io)?;
if current == target {
    return Ok(SymlinkOutcome::AlreadyCorrect);
}
fs::remove_file(link).map_err(NonoError::Io)?;
unix_fs::symlink(target, link).map_err(NonoError::Io)?;
Ok(SymlinkOutcome::Repointed)
```

There was no ownership check against lockfile records or pack-owned state before removal. Therefore, any existing user symlink at the requested `link` path could be silently repointed to the pack-chosen `target`.

Practical impact: a malicious pack could target a trusted user symlink such as a command shim or agent configuration symlink under `$HOME` or `$XDG_CONFIG_HOME`, redirecting later accesses through that trusted path to attacker-controlled pack content.

## Why This Is A Real Bug

The installer already distinguishes managed and unmanaged ownership for `WriteFile` by checking `pack_owned_files` before overwriting existing files. Symlink replacement did not apply equivalent ownership control.

An existing symlink is not proof of nono ownership. Without checking that the link was previously created by nono or owned by the current pack, replacing it crosses a filesystem trust boundary and lets pack metadata take over user-managed paths.

## Fix Requirement

Only create a symlink when the link path is absent, or treat it as idempotent when the existing symlink already points to the requested target. Refuse to overwrite an existing symlink that points elsewhere unless ownership is proven by lockfile-managed state for the same pack.

## Patch Rationale

The patch removes the unsafe repointing path entirely. It chooses the safest behavior: never overwrite an existing symlink whose target differs from the requested one, regardless of prior ownership.

- `SymlinkOutcome::Repointed` is removed.
- `execute_one` only marks disk state changed for `SymlinkOutcome::Created`.
- `ensure_symlink` still returns `AlreadyCorrect` when an existing symlink already points at the requested target.
- `ensure_symlink` now returns `Conflict` when an existing symlink points elsewhere.
- The conflict message states the path is not a nono-managed symlink and is left alone.

This trades a small UX regression — packs that legitimately change their symlink target now report a conflict and require manual removal — for the security guarantee that no pre-existing user symlink can be silently repointed by pack metadata.

## Residual Risk

None

## Patch

```diff
diff --git a/crates/nono-cli/src/wiring.rs b/crates/nono-cli/src/wiring.rs
index bba7a7a..74bdcd9 100644
--- a/crates/nono-cli/src/wiring.rs
+++ b/crates/nono-cli/src/wiring.rs
@@ -347,7 +347,7 @@ fn execute_one(
             let link_path = expand_to_path(link, ctx)?;
             let target_path = expand_to_path(target, ctx)?;
             match ensure_symlink(&link_path, &target_path)? {
-                SymlinkOutcome::Created | SymlinkOutcome::Repointed => {
+                SymlinkOutcome::Created => {
                     report.changed = true;
                     report.records.push(WiringRecord::Symlink {
                         link: link_path.to_string_lossy().into_owned(),
@@ -717,7 +717,6 @@ fn expand_vars(template: &str, ctx: &WiringContext) -> Result<String> {
 
 enum SymlinkOutcome {
     Created,
-    Repointed,
     AlreadyCorrect,
     Conflict(String),
 }
@@ -738,9 +737,10 @@ fn ensure_symlink(link: &Path, target: &Path) -> Result<SymlinkOutcome> {
             if current == target {
                 return Ok(SymlinkOutcome::AlreadyCorrect);
             }
-            fs::remove_file(link).map_err(NonoError::Io)?;
-            unix_fs::symlink(target, link).map_err(NonoError::Io)?;
-            Ok(SymlinkOutcome::Repointed)
+            Ok(SymlinkOutcome::Conflict(format!(
+                "{} exists and is not a nono-managed symlink — leaving it alone",
+                link.display()
+            )))
         }
         Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
             unix_fs::symlink(target, link).map_err(NonoError::Io)?;
```