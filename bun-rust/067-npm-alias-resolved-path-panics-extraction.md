# npm alias resolved path panics extraction

## Classification

Denial of service, medium severity, certain confidence.

## Affected Locations

`src/install/yarn.rs:309`

## Summary

A malformed npm-alias `resolved` value in a Yarn v1 lockfile can panic lockfile migration. When `resolved` starts with `/-/`, package-name extraction computes an invalid byte slice range `1..0`, terminating migration instead of rejecting or ignoring the malformed URL.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

Victim migrates a Yarn v1 `yarn.lock` containing an attacker-controlled npm-alias entry whose `resolved` field begins with `/-/`.

## Proof

Minimal triggering lock entry:

```text
# yarn lockfile v1

alias@npm:real-package@1.0.0:
  version "1.0.0"
  resolved "/-/real-package-1.0.0.tgz"
```

Execution path:

- `migrate_yarn_lockfile` detects an npm alias with `entry.resolved.is_some()` and calls `Entry::get_package_name_from_resolved_url(entry.resolved.unwrap())`.
- In `get_package_name_from_resolved_url`, `strings::index_of(url, b"/-/")` returns `dash_idx == 0` for `resolved "/-/real-package-1.0.0.tgz"`.
- The backward scan does not run because `i == 0`, leaving `last_slash == 0`.
- The scoped-package guard `last_slash < dash_idx && url[last_slash + 1] == b'@'` is false because `0 < 0` is false.
- The previous fallback returned `&url[last_slash + 1..dash_idx]`, i.e. `&url[1..0]`.
- Rust panics on that invalid slice range, aborting/failing migration.

## Why This Is A Real Bug

The input is parsed from the lockfile and reaches package-name extraction without validation. A single npm-alias entry with a `resolved` field beginning `/-/` deterministically causes an invalid slice range. This is not a recoverable parse error; it is a process panic during lockfile migration, so malformed lockfile input can deny service to the migration operation.

## Fix Requirement

Do not slice unless a slash was found before the `/-/` separator. If `dash_idx == 0` or `last_slash >= dash_idx`, package-name extraction must return `None` or otherwise avoid slicing.

## Patch Rationale

The patch adds the same ordering precondition to the fallback slice that already protects the scoped-package branch:

```diff
-            } else {
+            } else if last_slash < dash_idx {
                 return Some(&url[last_slash + 1..dash_idx]);
             }
```

For normal URLs where a package path exists before `/-/`, behavior is unchanged. For malformed URLs beginning with `/-/`, the function now falls through to `None`, allowing callers to use their existing fallback behavior instead of panicking.

## Residual Risk

None

## Patch

`067-npm-alias-resolved-path-panics-extraction.patch`

```diff
diff --git a/src/install/yarn.rs b/src/install/yarn.rs
index a0f87af34b..2eb10279aa 100644
--- a/src/install/yarn.rs
+++ b/src/install/yarn.rs
@@ -319,7 +319,7 @@ impl<'a> Entry<'a> {
 
             if last_slash < dash_idx && url[last_slash + 1] == b'@' {
                 return Some(&url[second_last_slash + 1..dash_idx]);
-            } else {
+            } else if last_slash < dash_idx {
                 return Some(&url[last_slash + 1..dash_idx]);
             }
         }
```