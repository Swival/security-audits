# procfs self grant widens to all procfs

## Classification

Information disclosure, low severity, certain confidence.

## Affected Locations

`crates/nono/src/capability.rs:1207` (`CapabilitySet::widen_procfs_self_to_proc`)

## Summary

A read-only capability requested for `/proc/self` is rewritten so that its
resolved Landlock path becomes `/proc`. Because filesystem directory
capabilities are recursive, a self-only procfs grant becomes a recursive read
grant covering every entry beneath `/proc`, including `/proc/<other-pid>`. A
sandboxed process can therefore read procfs metadata for other processes when
normal procfs DAC permissions allow it.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- Linux sandbox.
- The capability set contains a read directory capability whose `original`
  path is exactly `/proc/self` or `/proc/self/`.
- The default `system_read_linux_core` policy group at
  `crates/nono-cli/data/policy.json:249` ships such a grant.

## Proof

`CapabilitySet::widen_procfs_self_to_proc` rewrites any read capability whose
original path is `/proc/self` or `/proc/self/` by setting `cap.resolved` to
`/proc`. The Linux sandbox emits recursive Landlock `PathBeneath` rules for
directory capabilities (`crates/nono/src/sandbox/linux.rs:651`), and read
access maps to `ReadFile | ReadDir | Execute` (`crates/nono/src/sandbox/linux.rs:293`).
With `resolved = /proc`, Landlock allows reads anywhere under `/proc`.

`CapabilitySet::path_covered_with_access` (`crates/nono/src/capability.rs:1576`)
treats any path that starts with a directory capability's `resolved` path as
covered, so the over-grant also affects in-process capability checks that
consult the capability set, not just kernel-level Landlock rules.

## Why The Code Looks This Way

The doc comment on `widen_procfs_self_to_proc` explains the intent:
grandchild processes (e.g. `nono -> sh -> bun`) need to read their own procfs
entries, but Landlock rules are fixed at sandbox setup using the direct
child's PID. Widening to `/proc` is the existing trade-off that lets any
descendant resolve `/proc/self/...` successfully.

## Threat Model Assessment

The widening over-grants more than the user typically expects. However:

- The information disclosed is procfs metadata for same-user processes,
  which is generally already visible to the user through tools like `ps -ef`.
  Procfs DAC permissions still apply.
- The sandbox does not promise process-set confidentiality from same-user
  processes.

In nono's threat model (an adversarial sandboxed child trying to escape) the
practical impact is bounded enumeration of host processes that the invoking
user could already enumerate. This is information disclosure, not a sandbox
escape, and the severity is correspondingly low.

## Fix Requirement

A correct fix must either:

1. Narrow the grant to specific descendant files that grandchildren actually
   need to open (for example `/proc/<pid>/cmdline`, `/proc/<pid>/status`),
   while still keeping them resolvable across forks. This is non-trivial
   because Landlock rules cannot be templated on a runtime PID.
2. Or, route procfs reads through a supervisor that re-checks the requested
   path against the active child PID. This is what capability-elevation mode
   already does via seccomp-notify but it is unavailable in static supervised
   mode (`crates/nono-cli/src/exec_strategy.rs:753`).
3. Or, accept the trade-off explicitly and document that `/proc/self` grants
   widen to `/proc` for descendant compatibility.

The patch below takes the simplest course (option closest to (1) at the
expense of grandchild support): it removes the widening entirely. This
restores the policy to least privilege but **breaks grandchild self-procfs
reads** (`/proc/self/cmdline` etc. from a forked descendant will fail with
EACCES). Consumers who rely on grandchild procfs access — including the
documented `nono -> sh -> bun` flow — must adopt a different mechanism, such
as routing through capability elevation.

## Patch Rationale

Drop the widening loop. The capability set still contains the read grant for
`/proc/<direct-child-pid>` via `remap_procfs_self_references`, so the direct
child still reads its own procfs entries. Grandchild self-reads regress and
must be re-introduced via supervisor mediation if needed.

## Residual Risk

After the patch, grandchild processes lose self-procfs read access. The
direct child's `/proc/self` still resolves correctly because
`remap_procfs_self_references` rewrites it to the child's PID before this
function runs.

## Patch

```diff
diff --git a/crates/nono/src/capability.rs b/crates/nono/src/capability.rs
index 43bcc54..dc6134a 100644
--- a/crates/nono/src/capability.rs
+++ b/crates/nono/src/capability.rs
@@ -1205,18 +1205,6 @@ impl CapabilitySet {
     /// Only applies to READ capabilities at the `/proc/self` level (not
     /// subdirectories like `/proc/self/fd` which may have write access).
     pub fn widen_procfs_self_to_proc(&mut self) {
-        for cap in &mut self.fs {
-            if cap.access == AccessMode::Read {
-                let is_proc_self_dir = cap
-                    .original
-                    .to_str()
-                    .map(|s| s == "/proc/self" || s == "/proc/self/")
-                    .unwrap_or(false);
-                if is_proc_self_dir {
-                    cap.resolved = std::path::PathBuf::from("/proc");
-                }
-            }
-        }
         self.deduplicate();
     }
```
