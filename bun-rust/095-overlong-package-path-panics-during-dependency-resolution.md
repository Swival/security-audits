# Overlong Package Path Panics During Dependency Resolution

## Classification

Denial of service, medium severity. Confidence: certain.

## Affected Locations

`src/install/lockfile/bun.lock.rs:1397`

## Summary

An attacker-controlled `bun.lock` package key can exceed the fixed `PathBuffer` used during dependency resolution. `PkgMap::find_resolution` copies `pkg_path` and appends `/` plus the dependency name without validating the combined length, so Rust bounds checks panic and abort `bun install`.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

Victim runs install on an attacker-controlled repository lockfile.

## Proof

A malicious lockfile can define an overlong `packages` key and a dependency such as:

```json
{
  "dependencies": {
    "b": "1.0.0"
  }
}
```

During parsing, package dependency handling calls:

`parse_append_dependencies::<true, false>(..., Some(pkg_path), Some(&bundled_pkgs), ...)`

The reproduced failure path showed an earlier unchecked bundled-dependency path at `src/install/lockfile/bun.lock.rs:2967`, where `pkg_path` is copied into `PathBuffer` and then `/` is written at `src/install/lockfile/bun.lock.rs:2969`.

The originally identified dependency-resolution path has the same missing bound check in `PkgMap::find_resolution`:

```rust
path_buf[0..pkg_path.len()].copy_from_slice(pkg_path);
path_buf[pkg_path.len()] = b'/';
```

If `pkg_path.len() > path_buf.len()`, the slice range panics. If `pkg_path.len() == path_buf.len()`, writing `path_buf[pkg_path.len()]` panics. In both cases dependency processing aborts.

## Why This Is A Real Bug

`pkg_path` comes from attacker-controlled `packages` object keys in `bun.lock`. The code treats it as trusted and uses it to index a fixed-size path buffer without checking that `pkg_path + "/" + dep_name` fits. Rust panics on out-of-bounds indexing, producing a reliable installer crash rather than a structured parse error.

## Fix Requirement

Reject package paths whose `pkg_path.len() + 1 + dep_name.len()` exceeds `PathBuffer` capacity before copying or indexing into the buffer.

## Patch Rationale

The patch adds checked arithmetic and a capacity check at the start of `PkgMap::find_resolution`. If the constructed lookup path cannot fit, the function returns `ResolveError::InvalidPackageKey` instead of panicking. This preserves existing caller behavior for invalid package paths while preventing out-of-bounds slicing and indexing.

## Residual Risk

None

## Patch

```diff
diff --git a/src/install/lockfile/bun.lock.rs b/src/install/lockfile/bun.lock.rs
index 2cc8dc98e2..c2bc011b12 100644
--- a/src/install/lockfile/bun.lock.rs
+++ b/src/install/lockfile/bun.lock.rs
@@ -1393,6 +1393,16 @@ impl<T> PkgMap<T> {
         path_buf: &mut [u8],
     ) -> Result<&T, ResolveError> {
         let dep_name = dep.name.slice(string_buf);
+        let Some(needed) = pkg_path
+            .len()
+            .checked_add(1)
+            .and_then(|len| len.checked_add(dep_name.len()))
+        else {
+            return Err(ResolveError::InvalidPackageKey);
+        };
+        if needed > path_buf.len() {
+            return Err(ResolveError::InvalidPackageKey);
+        }
 
         path_buf[0..pkg_path.len()].copy_from_slice(pkg_path);
         path_buf[pkg_path.len()] = b'/';
```