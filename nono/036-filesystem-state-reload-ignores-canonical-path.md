# Filesystem State Reload Ignores Canonical Path

## Classification

Security control failure, medium severity, certain confidence.

The library API `SandboxState::to_caps` is exported (`pub use state::SandboxState` in `crates/nono/src/lib.rs`), so external consumers reconstructing capabilities from on-disk JSON are exposed to the smuggle. Inside this repository, the CLI keeps its own `SandboxState` type and only invokes the library `to_caps` from `nono why --self`, which is a diagnostic command; the reconstructed capability set is queried, not applied to a new sandbox. The fix is still required for hygiene, library consumer safety, and parity with the unix socket reload path, but the realistic impact in the bundled CLI is misleading the user about effective grants rather than gaining new ones.

## Affected Locations

- `crates/nono/src/state.rs:104`

## Summary

`SandboxState::to_caps` reconstructs filesystem capabilities from serialized state using only `fs_cap.original`. It does not verify that the reconstructed capability's canonical `resolved` path matches the serialized `fs_cap.resolved` path.

An attacker who controls sandbox state JSON can set `original` to an attacker-chosen existing path while setting `resolved` to a trusted path. Reload accepts the state and grants access to the attacker-chosen path.

## Provenance

- Verified by Swival.dev Security Scanner: https://swival.dev
- Reproduced deterministically with crafted sandbox state JSON
- Patch provided in `036-filesystem-state-reload-ignores-canonical-path.patch`

## Preconditions

- Victim reloads attacker-controlled sandbox state JSON.
- The attacker-chosen `fs.original` path exists and passes `FsCapability::new_file` or `FsCapability::new_dir` validation.
- `fs.resolved` names a different trusted canonical path.

## Proof

The reload path is reachable through:

- `SandboxState::from_json`, which parses attacker-controlled JSON.
- `SandboxState::to_caps`, which reconstructs filesystem grants.

In the vulnerable code, `to_caps` parses the access mode, then calls:

```rust
FsCapability::new_file(&fs_cap.original, access)?
```

or:

```rust
FsCapability::new_dir(&fs_cap.original, access)?
```

The resulting capability is added with:

```rust
caps.add_fs(cap);
```

No check compares `cap.resolved` against `fs_cap.resolved`.

A crafted JSON state with `resolved=/tmp/.../trusted` and `original=/tmp/.../attacker` reloads successfully. The resulting filesystem capability has `resolved` equal to the attacker path and access `read+write`.

The analogous Unix socket reload path already rejects this class of mismatch by comparing reconstructed `cap.resolved` to serialized `sock.resolved`.

## Why This Is A Real Bug

The serialized state contains both `original` and canonical `resolved` paths. On reload, the canonical path is the security-relevant identity of the filesystem grant.

Ignoring `fs_cap.resolved` makes reload fail open:

- It accepts inconsistent serialized state.
- It grants access to the canonical path derived from attacker-controlled `original`.
- It does not enforce the canonical grant that was serialized.
- It diverges from the Unix socket reload validator, which rejects canonical path drift.

This violates the expected invariant that reloaded capability state preserves the serialized canonical filesystem grant.

## Fix Requirement

After reconstructing a filesystem capability from `fs_cap.original`, compare the reconstructed `cap.resolved` with serialized `fs_cap.resolved`.

If they differ, reject reload with a configuration parse error and do not add the capability.

## Patch Rationale

The patch adds the missing canonical path consistency check immediately after `FsCapability::new_file` / `FsCapability::new_dir` and before `caps.add_fs(cap)`.

This preserves the existing validation behavior:

- Paths are still revalidated through standard constructors.
- Existence and canonicalization checks still happen.
- Legitimate round trips continue to work when `resolved` is unchanged.

It also rejects both relevant failure modes:

- Crafted JSON where `original` and `resolved` intentionally disagree.
- Filesystem drift between save and reload, such as symlink target changes.

## Residual Risk

None

## Patch

```diff
diff --git a/crates/nono/src/state.rs b/crates/nono/src/state.rs
index ea8625a..57b7ff7 100644
--- a/crates/nono/src/state.rs
+++ b/crates/nono/src/state.rs
@@ -105,6 +105,14 @@ impl SandboxState {
             } else {
                 FsCapability::new_dir(&fs_cap.original, access)?
             };
+            if cap.resolved != fs_cap.resolved {
+                return Err(crate::error::NonoError::ConfigParse(format!(
+                    "filesystem grant canonical path drifted at state reload: \
+                     serialized resolved={}, actual resolved={}",
+                    fs_cap.resolved.display(),
+                    cap.resolved.display(),
+                )));
+            }
             caps.add_fs(cap);
         }
```