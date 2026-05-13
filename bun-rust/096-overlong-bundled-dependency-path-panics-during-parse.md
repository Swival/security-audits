# Overlong Bundled Dependency Path Panics During Parse

## Classification

Denial of service, medium severity. Confidence: certain.

## Affected Locations

`src/install/lockfile/bun.lock.rs:2967`

## Summary

Parsing an attacker-controlled `bun.lock` can panic when bundled dependency resolution constructs a `pkg_path/name` lookup in a fixed `PathBuffer` without first checking length. An overlong package key or dependency name causes Rust slice indexing to exceed buffer bounds, aborting install during lockfile parsing.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

Victim runs `bun install` or equivalent lockfile parsing on a repository containing an attacker-controlled `bun.lock`.

## Proof

A malicious `bun.lock` can include a `packages` entry whose key length exceeds `PathBuffer` capacity, or whose key plus `/` plus dependency name exceeds it:

```json
{
  "lockfileVersion": 1,
  "workspaces": { "": {} },
  "packages": {
    "<A repeated more than PathBuffer capacity>": [
      "pkg@1.0.0",
      "",
      { "dependencies": { "dep": "1.0.0" } }
    ]
  }
}
```

During `parse_into_binary_lockfile`, each package info object is parsed through `parse_append_dependencies::<true, false>`. With bundled checks enabled, the parser builds `bundled_location` in a fixed `PathBuffer` before consulting `bundled_pkgs.contains(...)`.

The vulnerable operations are:

```rust
path_buf[0..pkg_path.len()].copy_from_slice(pkg_path);
let remain = &mut path_buf[pkg_path.len()..];
remain[0] = b'/';
let remain = &mut remain[1..];
remain[0..name_str.len()].copy_from_slice(name_str);
let bundled_location = &path_buf[0..pkg_path.len() + 1 + name_str.len()];
```

If `pkg_path.len()` exceeds `path_buf.len()`, the first slice panics. If `pkg_path` fits but `pkg_path.len() + 1 + name_str.len()` exceeds capacity, later `remain` or final slice indexing panics. The package does not need to match a bundled package entry because the panic occurs before the lookup.

## Why This Is A Real Bug

The input is attacker-controlled repository content. The panic is reachable during normal parsing before validation rejects the malformed path. Rust bounds checks convert the unchecked fixed-buffer indexing into a process panic, so install aborts instead of returning a structured parse error.

## Fix Requirement

Before copying into `PathBuffer`, validate that `pkg_path.len() + 1 + name_str.len()` is no greater than the buffer length. On overflow or excessive length, return a parse error instead of indexing.

## Patch Rationale

The patch computes the full bundled lookup length with saturating addition:

```rust
let bundled_location_len = pkg_path.len().saturating_add(1).saturating_add(name_str.len());
```

It rejects oversized inputs before any slice operation:

```rust
if bundled_location_len > path_buf.len() {
    log.add_error(Some(source), key.loc, b"Package path and dependency name too long");
    return Err(ParseError::InvalidPackageKey);
}
```

After this check, all subsequent slices are bounded by `bundled_location_len <= path_buf.len()`, preventing the panic. The final slice uses the prevalidated length, avoiding repeated unchecked arithmetic.

## Residual Risk

None

## Patch

```diff
diff --git a/src/install/lockfile/bun.lock.rs b/src/install/lockfile/bun.lock.rs
index 2cc8dc98e2..1b47d2dba0 100644
--- a/src/install/lockfile/bun.lock.rs
+++ b/src/install/lockfile/bun.lock.rs
@@ -2964,12 +2964,17 @@ fn parse_append_dependencies<const CHECK_FOR_BUNDLED: bool, const IS_ROOT: bool>
                     let bundled_pkgs =
                         bundled_pkgs.expect("bundled_pkgs required when CHECK_FOR_BUNDLED");
                     let path_buf = &mut path_buf.as_mut().unwrap()[..];
+                    let bundled_location_len = pkg_path.len().saturating_add(1).saturating_add(name_str.len());
+                    if bundled_location_len > path_buf.len() {
+                        log.add_error(Some(source), key.loc, b"Package path and dependency name too long");
+                        return Err(ParseError::InvalidPackageKey);
+                    }
                     path_buf[0..pkg_path.len()].copy_from_slice(pkg_path);
                     let remain = &mut path_buf[pkg_path.len()..];
                     remain[0] = b'/';
                     let remain = &mut remain[1..];
                     remain[0..name_str.len()].copy_from_slice(name_str);
-                    let bundled_location = &path_buf[0..pkg_path.len() + 1 + name_str.len()];
+                    let bundled_location = &path_buf[0..bundled_location_len];
                     if bundled_pkgs.contains(bundled_location) {
                         dep.behavior.insert(Behavior::BUNDLED);
                     }
```