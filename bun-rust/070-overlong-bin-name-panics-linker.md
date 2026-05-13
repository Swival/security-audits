# Overlong Bin Name Panics Linker

## Classification

Denial of service, medium severity, confidence certain.

## Affected Locations

`src/install/bin.rs:1282`

`src/install/bin.rs:1479`

`src/install/bin.rs:1519`

## Summary

Attacker-controlled `package.json` `bin` names are copied into the fixed-size `abs_dest_buf` during bin linking without first checking remaining capacity. An overlong single-entry `bin` key or multi-entry `bin` map key makes the destination slice range exceed the buffer length, triggering a Rust bounds-check panic. Because the workspace builds with `panic = "abort"`, this aborts package installation before bin links complete.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

The finding was independently reproduced and patched.

## Preconditions

The installer processes attacker-controlled package `bin` metadata.

## Proof

A malicious package author can provide an overlong `package.json` `bin` key.

The reproduced flow is:

- `package.json` `bin` metadata reaches `Tag::NamedFile` for single-entry maps and `Tag::Map` for multi-entry maps.
- Packages with non-`None` bins are queued for linking.
- `PackageInstaller` calls `Linker::link(false)`.
- `Linker::link` builds the destination prefix in fixed `PathBuffer`-backed `abs_dest_buf`.
- For `Tag::NamedFile`, it copies `normalized_name` into `self.abs_dest_buf[dest_off..dest_off + normalized_name.len()]`.
- For `Tag::Map`, it copies `normalized_bin_dest` into `self.abs_dest_buf[dest_off..dest_off + normalized_bin_dest.len()]`.
- No capacity check exists before either slice operation.
- If the normalized bin name exceeds remaining `abs_dest_buf` capacity, Rust bounds checking panics.
- With `panic = "abort"`, the install process aborts.

## Why This Is A Real Bug

The copied name is attacker-controlled package metadata, not a trusted local path component. The destination buffer has a fixed maximum size, while `package.json` bin keys can be longer than the remaining capacity after the `.bin/` destination prefix. Rust prevents memory corruption with bounds checks, but the resulting panic still terminates installation, creating a reliable denial of service for consumers installing the malicious package.

## Fix Requirement

Reject overlong normalized bin names before copying them into `abs_dest_buf`.

The check must account for the current destination offset and reserve space for the trailing NUL byte written immediately after the copied name.

## Patch Rationale

The patch adds explicit length checks before the vulnerable copies in both affected `Linker::link` branches:

- `Tag::NamedFile`: checks `normalized_name.len()` against remaining destination buffer capacity from `dest_off`.
- `Tag::Map`: checks `normalized_bin_dest.len()` against remaining destination buffer capacity from `abs_dest_dir_end`.

On overflow risk, linking fails with `NameTooLong` instead of panicking. The comparison uses `>=` so one byte remains available for the NUL terminator written after the name.

## Residual Risk

None

## Patch

```diff
diff --git a/src/install/bin.rs b/src/install/bin.rs
index e73d41e5a1..5b3250f2b7 100644
--- a/src/install/bin.rs
+++ b/src/install/bin.rs
@@ -1462,6 +1462,10 @@ impl<'a> Linker<'a> {
                     if normalized_name.is_empty() || target.is_empty() {
                         return;
                     }
+                    if normalized_name.len() >= self.abs_dest_buf.len().saturating_sub(dest_off) {
+                        self.err = Some(bun_core::err!("NameTooLong"));
+                        return;
+                    }
 
                     // for normalizing `target`
                     let abs_target: &ZStr = {
@@ -1502,6 +1506,12 @@ impl<'a> Linker<'a> {
                             i += 2;
                             continue;
                         }
+                        if normalized_bin_dest.len()
+                            >= self.abs_dest_buf.len().saturating_sub(abs_dest_dir_end)
+                        {
+                            self.err = Some(bun_core::err!("NameTooLong"));
+                            return;
+                        }
 
                         let abs_target: &ZStr = {
                             let package_dir = &self.abs_target_buf[0..package_dir_len];
```