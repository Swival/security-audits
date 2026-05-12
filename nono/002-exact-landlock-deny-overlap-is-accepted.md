# exact Landlock deny-overlap is accepted

## Classification

security_control_failure, high severity, confidence certain

## Affected Locations

- `crates/nono-cli/src/policy.rs:1113` (`validate_deny_overlaps`)

## Summary

On Linux, `validate_deny_overlaps` was intended to reject `deny.access` paths that Landlock cannot enforce because Landlock is allow-list only. The validator rejected child overlaps but skipped exact directory allow/deny matches due to `*deny_path != cap.resolved`. An exact match therefore started the sandbox successfully while the allowed directory remained accessible.

## Provenance

- Verified by Swival.dev Security Scanner: https://swival.dev
- Reproduced from the provided trigger: a Linux policy with an allowed directory capability and a matching `deny_paths` entry for the same directory.

## Preconditions

- Target platform is Linux.
- Final filesystem capabilities contain an allowed directory.
- `deny_paths` contains the same directory path.
- The denied path is not removed by `apply_deny_overrides`.

## Proof

The vulnerable predicate was:

```rust
if deny_path.starts_with(&cap.resolved) && *deny_path != cap.resolved {
```

For an exact directory match:

```text
deny_path.starts_with(&cap.resolved) == true
*deny_path != cap.resolved == false
```

The conflict branch is skipped, `fatal_conflicts` remains empty, and `validate_deny_overlaps` returns `Ok(())`.

The later policy invariant test states the intended Linux rule explicitly: Landlock cannot enforce child overlaps or exact matches because “allowing + denying the same directory means the allow wins.”

## Why This Is A Real Bug

Landlock has no deny semantics; it grants access based on an allow-list. If a path is both allowed and denied in policy, the deny rule cannot remove the allow. Accepting exact overlap gives users a false security guarantee and leaves the supposedly denied directory accessible inside the sandbox.

## Fix Requirement

Reject any Linux deny path that is equal to or below an allowed directory capability. The conflict predicate must not exclude `deny_path == cap.resolved`.

## Patch Rationale

The patch removes the exact-match exclusion:

```diff
- if deny_path.starts_with(&cap.resolved) && *deny_path != cap.resolved {
+ if deny_path.starts_with(&cap.resolved) {
```

This aligns runtime validation with the documented invariant: a Landlock deny path is invalid whenever it is equal to or a child of an allowed directory. File capabilities remain skipped, preserving the existing behavior that file grants cannot cover directory subtrees.

## Residual Risk

None

## Patch

```diff
diff --git a/crates/nono-cli/src/policy.rs b/crates/nono-cli/src/policy.rs
index f8e5134..65a55a2 100644
--- a/crates/nono-cli/src/policy.rs
+++ b/crates/nono-cli/src/policy.rs
@@ -1109,8 +1109,8 @@ pub fn validate_deny_overlaps(deny_paths: &[PathBuf], caps: &CapabilitySet) -> R
             if cap.is_file {
                 continue; // File caps can't cover a directory subtree
             }
-            // Check if deny path is a child of an allowed directory
-            if deny_path.starts_with(&cap.resolved) && *deny_path != cap.resolved {
+            // Check if deny path is equal to or a child of an allowed directory
+            if deny_path.starts_with(&cap.resolved) {
                 let conflict = format!(
                     "deny '{}' overlaps allowed parent '{}' (source: {})",
                     deny_path.display(),
```