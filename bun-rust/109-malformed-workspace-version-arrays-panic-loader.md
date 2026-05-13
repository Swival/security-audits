# malformed workspace version arrays panic loader

## Classification

denial of service, medium severity

## Affected Locations

`src/install/lockfile/bun.lockb.rs:438`

## Summary

A malformed attacker-supplied `bun.lockb` can make the binary lockfile loader panic during install. The workspace metadata section deserializes key and value arrays independently, then uses the value array length to size the map before blindly copying the key array into it. If the key and value array lengths differ, `copy_from_slice` panics instead of returning a lockfile parse error, aborting dependency installation.

## Provenance

Reproduced and patched from a Swival.dev Security Scanner finding: https://swival.dev

Confidence: certain.

## Preconditions

- Victim runs install on a repository containing an attacker-supplied `bun.lockb`.
- The lockfile contains the valid binary lockfile prefix and `HAS_WORKSPACE_PACKAGE_IDS_TAG`.
- The workspace hash/version arrays, or workspace path/string arrays, have unequal element counts.

## Proof

The install loader opens `bun.lock` first, then `bun.lockb`, and passes binary lockfile bytes to `load_from_bytes`.

After the workspace tag is read, `buffers::read_array` trusts each array’s serialized absolute `start_pos` and `end_pos`, so the following vectors can have attacker-controlled and mutually inconsistent lengths:

- `workspace_package_name_hashes`
- `workspace_versions_list`
- `workspace_paths_hashes`
- `workspace_paths_strings`

The vulnerable path sets `workspace_versions` length from `workspace_versions_list.len()`, then executes:

```rust
lockfile
    .workspace_versions
    .keys_mut()
    .copy_from_slice(&workspace_package_name_hashes);
```

When `workspace_package_name_hashes.len() != workspace_versions_list.len()`, Rust panics because `copy_from_slice` requires equal-length slices. The same issue exists for `workspace_paths_hashes` and `workspace_paths_strings`.

The panic is not converted into `LoadResult::Err`, so install aborts.

## Why This Is A Real Bug

The binary lockfile is repository-controlled input. A malicious cloned project can include a syntactically plausible `bun.lockb` whose workspace arrays have unequal lengths. The loader reaches the workspace section during install and panics deterministically before dependency installation can complete. This is an attacker-controlled denial of service, not just malformed input rejection, because the malformed condition causes an uncontrolled panic rather than a handled `InvalidLockfile` error.

## Fix Requirement

Reject unequal workspace hash/version and path/string array lengths before reserving map capacity, setting entry length, or copying slices.

## Patch Rationale

The patch adds explicit length validation immediately after deserializing each related array pair:

- `workspace_package_name_hashes.len() == workspace_versions_list.len()`
- `workspace_paths_hashes.len() == workspace_paths_strings.len()`

If either invariant fails, the loader returns `InvalidLockfile`. This preserves the expected behavior for malformed lockfiles while preventing `copy_from_slice` from observing mismatched slice lengths.

## Residual Risk

None

## Patch

```diff
diff --git a/src/install/lockfile/bun.lockb.rs b/src/install/lockfile/bun.lockb.rs
index 905d5eb1c4..d19ecf0ebc 100644
--- a/src/install/lockfile/bun.lockb.rs
+++ b/src/install/lockfile/bun.lockb.rs
@@ -435,6 +435,10 @@ pub fn load(
                     // const block without specialization; rely on type-checked
                     // `ensure_total_capacity` + slice copy below to enforce it.
 
+                    if workspace_package_name_hashes.len() != workspace_versions_list.len() {
+                        return Err(bun_core::err!("InvalidLockfile"));
+                    }
+
                     lockfile
                         .workspace_versions
                         .ensure_total_capacity(workspace_versions_list.len())?;
@@ -460,6 +464,10 @@ pub fn load(
                     let workspace_paths_hashes: Vec<PackageNameHash> = buffers::read_array(stream)?;
                     let workspace_paths_strings: Vec<SemverString> = buffers::read_array(stream)?;
 
+                    if workspace_paths_hashes.len() != workspace_paths_strings.len() {
+                        return Err(bun_core::err!("InvalidLockfile"));
+                    }
+
                     lockfile
                         .workspace_paths
                         .ensure_total_capacity(workspace_paths_strings.len())?;
```