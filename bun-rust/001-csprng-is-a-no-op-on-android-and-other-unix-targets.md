# CSPRNG No-Op On Android And Unsupported Unix Targets

## Classification

Security control failure, high severity. Confidence: certain.

## Affected Locations

`src/bun_core/util.rs:2900`

## Summary

`csprng(bytes: &mut [u8])` is intended to fill caller-provided buffers with OS-backed cryptographically secure random bytes. Before the patch, Android and other unhandled Unix targets compiled none of the platform-specific write branches, so `csprng` returned successfully without modifying `bytes`.

## Provenance

Verified and reproduced from the Swival.dev Security Scanner finding: https://swival.dev

## Preconditions

- Binary is built for Android, where `target_os = "android"`.
- Or binary is built for another Unix target not covered by `linux`, `macos`, `ios`, `freebsd`, or `windows`.
- A caller requests random bytes through `csprng`.

## Proof

- `src/bun_core/util.rs` defines `pub fn csprng(bytes: &mut [u8])`.
- The only write-capable branches were gated on:
  - `#[cfg(target_os = "linux")]`
  - `#[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]`
  - `#[cfg(windows)]`
- Android uses `target_os = "android"`, not `target_os = "linux"`.
- Therefore, on Android no branch compiled into the function body.
- The resulting function returned normally without writing to the buffer.
- Security-sensitive reachable callers include WebCrypto random bytes in `src/runtime/webcore/Crypto.rs:358` and Node crypto random bytes in `src/runtime/node/node_crypto_binding.rs:271`, `:375`, `:527`, `:585`.

## Why This Is A Real Bug

The function is a CSPRNG security control and its API communicates successful in-place randomization by returning normally. On Android, it instead preserved the caller's prior buffer contents. Callers relying on random output could receive unchanged, predictable bytes, breaking cryptographic assumptions for WebCrypto, Node crypto, and any other randomness consumer.

## Fix Requirement

Android must use a supported OS CSPRNG implementation, or unsupported targets must fail at compile time rather than producing a successful no-op.

## Patch Rationale

The patch treats Android like Linux for this purpose by enabling the existing `getrandom(2)` path for both `target_os = "linux"` and `target_os = "android"`. It also adds a `compile_error!` for every remaining unsupported target so future unhandled platforms cannot silently compile a no-op CSPRNG.

## Residual Risk

None

## Patch

```diff
diff --git a/src/bun_core/util.rs b/src/bun_core/util.rs
index bd8e34a345..7cf0c27ec9 100644
--- a/src/bun_core/util.rs
+++ b/src/bun_core/util.rs
@@ -2898,7 +2898,7 @@ pub fn is_writable(fd: Fd) -> Pollable {
 // from. PERF(port): if a hot path needs the BoringSSL DRBG, install a
 // vtable hook from bun_runtime at startup.
 pub fn csprng(bytes: &mut [u8]) {
-    #[cfg(target_os = "linux")]
+    #[cfg(any(target_os = "linux", target_os = "android"))]
     {
         let mut filled = 0usize;
         while filled < bytes.len() {
@@ -2946,6 +2946,15 @@ pub fn csprng(bytes: &mut [u8]) {
             }
         }
     }
+    #[cfg(not(any(
+        target_os = "linux",
+        target_os = "android",
+        target_os = "macos",
+        target_os = "ios",
+        target_os = "freebsd",
+        windows,
+    )))]
+    compile_error!("unsupported platform for csprng");
 }
 
 // ── self_exe_path ─────────────────────────────────────────────────────────
```