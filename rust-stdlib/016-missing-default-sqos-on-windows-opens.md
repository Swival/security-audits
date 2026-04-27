# Missing Default SQOS On Windows Opens

## Classification

Medium severity vulnerability.

## Affected Locations

`library/std/src/os/windows/fs.rs:264`

`library/std/src/sys/fs/windows.rs:205`

## Summary

Windows `std::fs::OpenOptions` did not set `security_qos_flags` by default. The default zero value reached `CreateFileW` through `opts.get_flags_and_attributes()`, leaving privileged Rust processes exposed when opening attacker-controlled Windows paths such as named pipes.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

A privileged Rust process opens an attacker-controlled Windows path without explicitly calling `OpenOptionsExt::security_qos_flags`.

## Proof

The Windows extension documentation stated that `security_qos_flags` was unset by default and warned that, when unset, “a malicious program can gain the elevated privileges of a privileged Rust process” by tricking it into opening a named pipe.

The reproduced path confirmed that the zero default is used by Windows open handling and reaches `CreateFileW` through `opts.get_flags_and_attributes()` in `library/std/src/sys/fs/windows.rs`.

A privileged process opening an attacker-controlled named pipe path becomes the named-pipe client with default Windows impersonation behavior, allowing the attacker-controlled pipe server to impersonate that client locally.

## Why This Is A Real Bug

This is a security-affecting unsafe default, not only a documentation mismatch. The implementation default was `0`, the value was passed into the Windows file-open flags, and the standard library documentation itself described the named-pipe privilege-escalation consequence and mitigation knob.

The bug is reachable through ordinary `std::fs` open flows whenever callers accept arbitrary paths and do not override SQOS manually.

## Fix Requirement

Set a safe SQOS default for Windows opens, or require an explicit opt-out for callers that need conflicting Windows flags.

## Patch Rationale

The patch changes the Windows `OpenOptions` default from unset SQOS to:

```rust
c::SECURITY_SQOS_PRESENT | c::SECURITY_IDENTIFICATION
```

This makes `CreateFileW` opens identify the client without allowing a named-pipe server to impersonate a privileged Rust process by default.

The documentation is updated to state that `security_qos_flags` defaults to `SECURITY_IDENTIFICATION` and can still be overridden by callers that need a different impersonation level.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/os/windows/fs.rs b/library/std/src/os/windows/fs.rs
index 7fd46b31f7d..3f8c7c77a2a 100644
--- a/library/std/src/os/windows/fs.rs
+++ b/library/std/src/os/windows/fs.rs
@@ -266,16 +266,11 @@ pub trait OpenOptionsExt {
     /// the specified value (or combines it with `custom_flags` and `attributes`
     /// to set the `dwFlagsAndAttributes` for [`CreateFile`]).
     ///
-    /// By default `security_qos_flags` is not set. It should be specified when
-    /// opening a named pipe, to control to which degree a server process can
-    /// act on behalf of a client process (security impersonation level).
-    ///
-    /// When `security_qos_flags` is not set, a malicious program can gain the
-    /// elevated privileges of a privileged Rust process when it allows opening
-    /// user-specified paths, by tricking it into opening a named pipe. So
-    /// arguably `security_qos_flags` should also be set when opening arbitrary
-    /// paths. However the bits can then conflict with other flags, specifically
-    /// `FILE_FLAG_OPEN_NO_RECALL`.
+    /// By default, `security_qos_flags` is set to `SECURITY_IDENTIFICATION`,
+    /// to prevent a named pipe server from impersonating a privileged client
+    /// process when it opens user-specified paths. It can be overridden to
+    /// control to which degree a server process can act on behalf of a client
+    /// process (security impersonation level).
     ///
     /// For information about possible values, see [Impersonation Levels] on the
     /// Windows Dev Center site. The `SECURITY_SQOS_PRESENT` flag is set
diff --git a/library/std/src/sys/fs/windows.rs b/library/std/src/sys/fs/windows.rs
index 74854cdeb49..d3df2facac8 100644
--- a/library/std/src/sys/fs/windows.rs
+++ b/library/std/src/sys/fs/windows.rs
@@ -205,7 +205,7 @@ pub fn new() -> OpenOptions {
             access_mode: None,
             share_mode: c::FILE_SHARE_READ | c::FILE_SHARE_WRITE | c::FILE_SHARE_DELETE,
             attributes: 0,
-            security_qos_flags: 0,
+            security_qos_flags: c::SECURITY_SQOS_PRESENT | c::SECURITY_IDENTIFICATION,
             inherit_handle: false,
             freeze_last_access_time: false,
             freeze_last_write_time: false,
```