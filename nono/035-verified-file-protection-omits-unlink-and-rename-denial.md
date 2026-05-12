# Verified File Protection Omits Unlink And Rename Denial

## Classification

Security control failure, high severity.

Confidence: certain.

## Affected Locations

- `crates/nono-cli/src/instruction_deny.rs:75`

## Summary

The macOS Seatbelt verified-file immutability control only emitted `(deny file-write-data ...)` for verified paths. That denied direct content writes but did not deny unlink, rename, or replacement operations when the parent directory remained writable. A sandboxed child with directory write access could remove or rename a verified file and create attacker-controlled content at the same path after the trust scan had already approved it.

## Provenance

- Verified by runtime reproduction using a nono-like Seatbelt profile.
- Originally identified by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- macOS Seatbelt sandbox is in use.
- The verified file path is protected through `write_protect_verified_files`.
- The parent directory has write access in the sandbox profile.
- The sandboxed child can invoke filesystem operations such as unlink, rename, or create.

## Proof

The affected implementation documented and generated only literal `file-write-data` deny rules for verified files:

```rust
let deny_rule = format!("(deny file-write-data (literal \"{path_str}\"))");
caps.add_platform_rule(deny_rule)?;
```

The same `file-write-data` operation was used for the canonicalized path rule.

The control is reachable during launch because verified paths from the pre-exec scan are passed into `write_protect_verified_files` at `crates/nono-cli/src/launch_runtime.rs:321`, and read capabilities are then added for those same paths at `crates/nono-cli/src/launch_runtime.rs:324`.

Parent directory write access is practical because the default policy grants write access to temporary locations including `/tmp`, `/private/tmp`, `/var/folders`, and `$TMPDIR` at `crates/nono-cli/data/policy.json:287`.

Runtime reproduction showed:

- Direct overwrite of the verified file was denied.
- `rm path && create path` succeeded.
- `mv evil path` succeeded.
- Later path-based reads observed attacker-controlled replacement content at the previously verified path.

## Why This Is A Real Bug

The module promises structural immutability for files that pass the pre-exec trust scan, even when the parent directory is writable. `file-write-data` only blocks data writes to the file object. It does not cover directory-entry mutations such as unlinking the path, renaming over the path, or recreating the path with new content. Because the trust decision is path-based and occurs before execution, successful replacement invalidates the security property: the path remains trusted, but its contents become attacker-controlled.

## Fix Requirement

The Seatbelt rule for each verified path must deny all write-class operations that can modify or replace the path, including direct writes, unlink, rename, and creation/replacement through directory-entry operations.

## Patch Rationale

The patch changes the generated Seatbelt operation from `file-write-data` to `file-write*` for both the original and canonical verified paths:

```rust
let deny_rule = format!("(deny file-write* (literal \"{path_str}\"))");
```

This broadens the literal deny rule to cover the full Seatbelt file-write operation class instead of only content writes. Because Seatbelt deny rules take precedence over broader directory-level allow rules, the verified path remains protected even when its parent directory is writable.

The documentation and test assertion are updated to match the stronger `file-write*` rule.

## Residual Risk

None

## Patch

```diff
diff --git a/crates/nono-cli/src/instruction_deny.rs b/crates/nono-cli/src/instruction_deny.rs
index 2900422..df7cd1d 100644
--- a/crates/nono-cli/src/instruction_deny.rs
+++ b/crates/nono-cli/src/instruction_deny.rs
@@ -1,7 +1,7 @@
 //! Write-protection rules for verified files (macOS Seatbelt)
 //!
 //! After the pre-exec trust scan verifies files, this module injects
-//! literal `(deny file-write-data ...)` rules into the Seatbelt profile
+//! literal `(deny file-write* ...)` rules into the Seatbelt profile
 //! for each verified file. This makes verified files structurally immutable
 //! at the kernel level — the agent cannot tamper with them even though the
 //! parent directory has write access granted.
@@ -27,7 +27,7 @@ use std::path::Path;
 /// Write-protect verified files in the Seatbelt profile.
 ///
 /// For each verified file path, adds a
-/// `(deny file-write-data (literal ...))` rule to prevent modification.
+/// `(deny file-write* (literal ...))` rule to prevent modification.
 ///
 /// On macOS, handles symlinks by emitting rules for both the original
 /// path and the canonical path when they differ (e.g., `/tmp/` vs
@@ -59,7 +59,7 @@ pub fn write_protect_verified_files(
     Ok(())
 }
 
-/// Add a `(deny file-write-data (literal ...))` rule for a verified file.
+/// Add a `(deny file-write* (literal ...))` rule for a verified file.
 ///
 /// This prevents modification of signed files even when the parent
 /// directory has write access granted. The deny rule takes precedence over
@@ -72,7 +72,7 @@ fn add_literal_write_deny(caps: &mut CapabilitySet, path: &Path) -> Result<()> {
     let path_str = path.display().to_string();
     validate_seatbelt_path(&path_str)?;
 
-    let deny_rule = format!("(deny file-write-data (literal \"{path_str}\"))");
+    let deny_rule = format!("(deny file-write* (literal \"{path_str}\"))");
     caps.add_platform_rule(deny_rule)?;
 
     // Handle macOS symlinks: emit rule for canonical path too
@@ -80,7 +80,7 @@ fn add_literal_write_deny(caps: &mut CapabilitySet, path: &Path) -> Result<()> {
         if canonical != path {
             let canonical_str = canonical.display().to_string();
             validate_seatbelt_path(&canonical_str)?;
-            let canonical_rule = format!("(deny file-write-data (literal \"{canonical_str}\"))");
+            let canonical_rule = format!("(deny file-write* (literal \"{canonical_str}\"))");
             caps.add_platform_rule(canonical_rule)?;
         }
     }
@@ -131,7 +131,7 @@ mod tests {
         assert!(
             rules
                 .iter()
-                .any(|r| r.contains("deny file-write-data")
+                .any(|r| r.contains("deny file-write*")
                     && r.contains(&file.display().to_string()))
         );
         // Should NOT have any read-deny rules
```