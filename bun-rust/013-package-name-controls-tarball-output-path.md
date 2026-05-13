# package name controls tarball output path

## Classification

Path traversal, medium severity. Confidence: certain.

## Affected Locations

`src/runtime/cli/pack_command.rs:3139`

## Summary

`bun pack` derived the default tarball output filename from `package.json` `name` without neutralizing path separators. An attacker-controlled package name such as `../pwn` caused the tarball destination to resolve outside the intended workspace directory when the victim packed the package without an explicit filename.

## Provenance

Verified finding from Swival.dev Security Scanner: https://swival.dev

## Preconditions

Victim runs `bun pack` on an attacker-controlled package.

Victim does not provide an explicit pack filename.

The attacker controls `package.json` `name`.

## Proof

The pack flow reads `package_name` from `package.json` and later computes the output path through `tarball_destination`.

`tarball_destination` appends the generated filename directly:

```rust
write!(
    &mut cursor,
    "/{}\x00",
    fmt_tarball_filename(package_name, package_version, TarballNameStyle::Normalize),
);
```

For non-scoped package names, the formatter previously emitted the raw package name into `{name}-{version}.tgz`:

```rust
write!(
    f,
    "{}-{}.tgz",
    bstr::BStr::new(self.package_name),
    bstr::BStr::new(self.package_version),
)
```

Thus a package name of `../pwn` with version `1.0.0` produced a destination like:

```text
/home/victim/project/pkg/../pwn-1.0.0.tgz
```

The path was then passed to archive creation via `archive.write_open_filename(abs_tarball_dest)`, causing the OS to resolve the `..` component and write the tarball outside the package directory.

## Why This Is A Real Bug

The package name is attacker-controlled package metadata, not a trusted filesystem path component.

The vulnerable path requires no unusual filesystem setup: `../pwn-1.0.0.tgz` targets the parent directory, which normally exists.

The tarball is actually opened for writing at the computed path, so the impact is an attacker-influenced file write location subject to the victim process permissions.

## Fix Requirement

Default tarball filenames must not preserve path separators from package names. Package names used in generated output filenames must either be rejected when they contain separators or transformed into safe basename-like filename components.

## Patch Rationale

The patch introduces `fmt_tarball_filename_part`, which formats each package-name component while replacing both `/` and `\` with `-`.

The existing scoped-package behavior is preserved: scoped names are still split into scope and name portions, but each portion is now separator-neutralized before being written into the tarball filename.

Non-scoped package names are now also separator-neutralized before being combined with the version and `.tgz` suffix.

`TarballNameStyle::Raw` remains unchanged, limiting the behavioral change to normalized generated tarball filenames.

## Residual Risk

None

## Patch

```diff
diff --git a/src/runtime/cli/pack_command.rs b/src/runtime/cli/pack_command.rs
index 497239f04d..752b019a0e 100644
--- a/src/runtime/cli/pack_command.rs
+++ b/src/runtime/cli/pack_command.rs
@@ -3136,6 +3136,27 @@ pub struct TarballNameFormatter<'a> {
     style: TarballNameStyle,
 }
 
+fn fmt_tarball_filename_part(part: &[u8]) -> TarballNamePartFormatter<'_> {
+    TarballNamePartFormatter { part }
+}
+
+struct TarballNamePartFormatter<'a> {
+    part: &'a [u8],
+}
+
+impl<'a> fmt::Display for TarballNamePartFormatter<'a> {
+    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
+        let mut start = 0;
+        for (i, &byte) in self.part.iter().enumerate() {
+            if byte == b'/' || byte == b'\\' {
+                write!(f, "{}-", bstr::BStr::new(&self.part[start..i]))?;
+                start = i + 1;
+            }
+        }
+        write!(f, "{}", bstr::BStr::new(&self.part[start..]))
+    }
+}
+
 impl<'a> fmt::Display for TarballNameFormatter<'a> {
     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
         if self.style == TarballNameStyle::Raw {
@@ -3154,8 +3175,8 @@ impl<'a> fmt::Display for TarballNameFormatter<'a> {
                     return write!(
                         f,
                         "{}-{}-{}.tgz",
-                        bstr::BStr::new(&self.package_name[1..][..slash - 1]),
-                        bstr::BStr::new(&self.package_name[slash + 1..]),
+                        fmt_tarball_filename_part(&self.package_name[1..][..slash - 1]),
+                        fmt_tarball_filename_part(&self.package_name[slash + 1..]),
                         bstr::BStr::new(self.package_version),
                     );
                 }
@@ -3164,7 +3185,7 @@ impl<'a> fmt::Display for TarballNameFormatter<'a> {
             return write!(
                 f,
                 "{}-{}.tgz",
-                bstr::BStr::new(&self.package_name[1..]),
+                fmt_tarball_filename_part(&self.package_name[1..]),
                 bstr::BStr::new(self.package_version),
             );
         }
@@ -3172,7 +3193,7 @@ impl<'a> fmt::Display for TarballNameFormatter<'a> {
         write!(
             f,
             "{}-{}.tgz",
-            bstr::BStr::new(self.package_name),
+            fmt_tarball_filename_part(self.package_name),
             bstr::BStr::new(self.package_version),
         )
     }
```