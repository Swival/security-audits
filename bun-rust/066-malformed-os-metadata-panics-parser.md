# Malformed `os` Metadata Panics Yarn Lockfile Parser

## Classification

Denial of service, medium severity.

## Affected Locations

`src/install/yarn.rs:508` (`os`)
`src/install/yarn.rs:516` (`cpu`)

## Summary

A malformed Yarn v1 lockfile entry with single-byte `os` metadata can panic the migration parser. The parser slices `value[1..value.len() - 1]` without first verifying that the value is a bracketed list. For `os x`, the parsed value is `x`, so the slice range becomes `1..0`, which panics and terminates migration before a lockfile is produced.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

Victim runs Yarn lockfile migration on an attacker-controlled repository.

## Proof

Minimal malicious `yarn.lock`:

```text
# yarn lockfile v1
foo@1.0.0:
  version "1.0.0"
  os x
```

Reachability:

- `migrate_yarn_lockfile` accepts repository `yarn.lock` bytes after checking only for `# yarn lockfile v1`.
- It calls `yarn_lock.parse(data)` before reading `package.json`.
- `YarnLock::parse` parses the indented line `os x` as key `os` and value `x`.
- The `os` branch evaluates `&value[1..value.len() - 1]`.
- For `value == b"x"`, that becomes `&value[1..0]`, an invalid Rust slice range.
- Rust panics on the invalid range, terminating the migration process.

## Why This Is A Real Bug

The input is attacker-controlled repository content and is processed during lockfile migration. No prior syntax validation rejects malformed `os` metadata, and the failing operation is an unchecked slice on untrusted input. The resulting panic prevents migration from producing a lockfile, which is a practical input-triggered denial of service.

## Fix Requirement

Validate that `os` metadata is bracketed before slicing. The parser must only evaluate `value[1..value.len() - 1]` when `value` starts with `[` and ends with `]`.

## Patch Rationale

The patch gates both the `os` and `cpu` parsing branches on `value.starts_with(b"[") && value.ends_with(b"]")`. The same unchecked slice exists in the `cpu` branch and is fixed identically. This preserves behavior for valid Yarn metadata such as `os ["darwin", "linux"]` while avoiding the invalid slice for malformed values such as `os x` or `cpu y`.

## Residual Risk

None

## Patch

```diff
diff --git a/src/install/yarn.rs b/src/install/yarn.rs
index a0f87af34b..35e9ed6b73 100644
--- a/src/install/yarn.rs
+++ b/src/install/yarn.rs
@@ -503,14 +503,14 @@ impl<'a> YarnLock<'a> {
                         }
                     } else if key == b"integrity" {
                         entry.integrity = Some(value);
-                    } else if key == b"os" {
+                    } else if key == b"os" && value.starts_with(b"[") && value.ends_with(b"]") {
                         let mut os_list: Vec<&'a [u8]> = Vec::new();
                         let mut os_it = strings::split(&value[1..value.len() - 1], b",");
                         while let Some(os) = os_it.next() {
                             let trimmed_os = strings::trim(os, b" \"");
                             os_list.push(trimmed_os);
                         }
                         entry.os = Some(os_list);
-                    } else if key == b"cpu" {
+                    } else if key == b"cpu" && value.starts_with(b"[") && value.ends_with(b"]") {
                         let mut cpu_list: Vec<&'a [u8]> = Vec::new();
                         let mut cpu_it = strings::split(&value[1..value.len() - 1], b",");
                         while let Some(cpu) = cpu_it.next() {
```