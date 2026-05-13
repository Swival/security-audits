# Malformed package script value panics

## Classification

Denial of service, medium severity, certain confidence.

## Affected Locations

`src/runtime/cli/create_command.rs:1315`

## Summary

`bun create` trusted attacker-controlled `package.json` script values to be strings. A GitHub template containing a valid JSON `scripts` object with a non-string value caused `CreateCommand::exec` to unwrap `None` and panic before project creation completed.

## Provenance

Verified from the supplied source, reproducer, and patch. Initially reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- Victim runs `bun create` on an attacker-controlled GitHub repository.
- The repository tarball includes `package.json`.
- `--no-package-json` is not set.
- `package.json` has a top-level `scripts` object with at least one non-string script value.

## Proof

A malicious repository can include:

```json
{
  "scripts": {
    "build": 1
  }
}
```

`CreateCommand::exec` fetches the GitHub tarball through `Example::fetch_from_github`, extracts it, plucks `package.json`, parses it, and processes the `scripts` property.

Before the patch, each script value was read as:

```rust
props.slice()[i].value.unwrap().data.e_string().unwrap().data.slice()
```

For `"build": 1`, `e_string()` returns `None`. The following `unwrap()` panics, terminating `bun create`.

## Why This Is A Real Bug

The input is attacker-controlled through a GitHub repository tarball, and the malformed value is valid JSON. `bun create owner/repo` processes `package.json` by default, so a victim using normal command behavior reaches the vulnerable path. The panic prevents project creation and produces a concrete denial of service.

## Fix Requirement

Check that each `scripts` entry has a present value and that the value is a string before reading, pruning, or rewriting it. Non-string or missing script values must not panic.

## Patch Rationale

The patch replaces chained `unwrap()` calls with `let Some(...)` checks. If a script entry has no value or has a non-string value, it is preserved and skipped by the string-specific rewrite/prune logic. String script values continue through the existing handling unchanged.

## Residual Risk

None

## Patch

```diff
diff --git a/src/runtime/cli/create_command.rs b/src/runtime/cli/create_command.rs
index 79fefcd6ec..9bcbb3be93 100644
--- a/src/runtime/cli/create_command.rs
+++ b/src/runtime/cli/create_command.rs
@@ -1312,14 +1312,21 @@ impl CreateCommand {
                                     let mut script_property_i: usize = 0;
 
                                     while script_property_i < scripts_properties.len() {
-                                        let script = scripts_properties[script_property_i]
-                                            .value
-                                            .unwrap()
-                                            .data
-                                            .e_string()
-                                            .unwrap()
-                                            .data
-                                            .slice();
+                                        let Some(script_value) = scripts_properties[script_property_i].value else {
+                                            scripts_properties
+                                                .swap(script_property_out_i, script_property_i);
+                                            script_property_out_i += 1;
+                                            script_property_i += 1;
+                                            continue;
+                                        };
+                                        let Some(script_value) = script_value.data.e_string() else {
+                                            scripts_properties
+                                                .swap(script_property_out_i, script_property_i);
+                                            script_property_out_i += 1;
+                                            script_property_i += 1;
+                                            continue;
+                                        };
+                                        let script = script_value.data.slice();
 
                                         if strings::contains(script, b"react-scripts start")
                                             || strings::contains(script, b"next dev")
```