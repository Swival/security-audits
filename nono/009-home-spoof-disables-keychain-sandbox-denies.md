# HOME-derived keychain check can be spoofed if env is untrusted

## Classification

defense_in_depth, low severity, confidence certain

## Affected Locations

- `crates/nono/src/sandbox/macos.rs:253`

## Summary

`has_explicit_keychain_db_access` derives the current user's keychain database
paths from `std::env::var("HOME")`. The helper returns `true` when a capability
matches `$HOME/Library/Keychains/login.keychain-db` or
`$HOME/Library/Keychains/metadata.keychain-db`, and `generate_profile` then
omits the Mach-lookup denies for `com.apple.SecurityServer`,
`com.apple.securityd`, `com.apple.security.keychaind`, `com.apple.secd` and
`com.apple.security.agent`. Because `HOME` is an untrusted-by-default
environment variable, any caller that builds a `CapabilitySet` with
attacker-controlled `HOME` plus a matching capability path can suppress those
denies.

## Threat Model Note

In nono's stated threat model the CLI is invoked by a trusted user and the
adversary is the sandboxed child. The child cannot influence the parent's
`HOME` or `CapabilitySet`, so this is not a sandbox-escape primitive in the
shipping CLI today.

However, the nono library is documented as policy-free and is intended to be
embedded by other tools. A library function that depends on `HOME` is a
footgun for embedders that pass through environment values from a less trusted
source. Using the OS user database makes the helper independent of an
attacker-mutable environment variable.

## Provenance

- Reported by Swival.dev Security Scanner: https://swival.dev
- Patched by `009-home-spoof-disables-keychain-sandbox-denies.patch`

## Preconditions

- An embedder builds a `CapabilitySet` while running under untrusted `HOME`.
- That embedder adds a filesystem capability whose path matches the forged
  `$HOME/Library/Keychains/login.keychain-db` or metadata variant.

## Why This Is Still Worth Fixing

`has_explicit_keychain_db_access` is the gate that decides whether the
profile keeps the keychain Mach-lookup denies. Driving that gate from a
trusted source (the passwd entry for the effective uid) closes off the
spoofing path entirely and removes a class of misuse for downstream embedders.
The change has no impact on the documented CLI flow because nono's CLI runs
under the invoking user's real `HOME`, which already matches the passwd entry.

## Fix Requirement

Derive the user's keychain database paths from a trusted source rather than
the `HOME` environment variable.

## Patch Rationale

The patch resolves the effective user's home directory via `libc::getuid()`
and `libc::getpwuid()`, reading `pw_dir` from the passwd entry. `pw_dir` is
decoded as raw bytes via `CStr` and `OsStr::from_bytes` so non-UTF-8 home
directories are handled losslessly. The recognised paths are unchanged.

## Residual Risk

None for the helper itself. Embedders that pass through other untrusted env
values are responsible for sanitising their own inputs.

## Patch

```diff
diff --git a/crates/nono/src/sandbox/macos.rs b/crates/nono/src/sandbox/macos.rs
index 47273ad..a0006db 100644
--- a/crates/nono/src/sandbox/macos.rs
+++ b/crates/nono/src/sandbox/macos.rs
@@ -8,8 +8,9 @@
 use crate::capability::{AccessMode, CapabilitySet, NetworkMode};
 use crate::error::{NonoError, Result};
 use crate::sandbox::SupportInfo;
-use std::ffi::{CStr, CString};
+use std::ffi::{CStr, CString, OsStr};
 use std::os::raw::c_char;
+use std::os::unix::ffi::OsStrExt;
 use std::path::Path;
 use std::ptr;
 use tracing::{debug, info};
@@ -251,12 +252,18 @@ fn path_filters_for_cap(cap: &crate::capability::FsCapability) -> Result<Vec<Str
 ///
 /// This is a narrow opt-in for tools that need OAuth/session refresh via macOS Keychain.
 fn has_explicit_keychain_db_access(caps: &CapabilitySet) -> bool {
-    let user_keychain_dbs = std::env::var("HOME").ok().map(|home| {
-        [
-            Path::new(&home).join("Library/Keychains/login.keychain-db"),
-            Path::new(&home).join("Library/Keychains/metadata.keychain-db"),
-        ]
-    });
+    let user_keychain_dbs = unsafe {
+        let passwd = libc::getpwuid(libc::getuid());
+        if passwd.is_null() || (*passwd).pw_dir.is_null() {
+            None
+        } else {
+            let home = OsStr::from_bytes(CStr::from_ptr((*passwd).pw_dir).to_bytes());
+            Some([
+                Path::new(home).join("Library/Keychains/login.keychain-db"),
+                Path::new(home).join("Library/Keychains/metadata.keychain-db"),
+            ])
+        }
+    };
     let system_keychain_dbs = [
         Path::new("/Library/Keychains/login.keychain-db").to_path_buf(),
         Path::new("/Library/Keychains/metadata.keychain-db").to_path_buf(),
```
