# Encoded Slash Check Runs After Percent Decoding

## Classification

Policy bypass, medium severity, confidence certain.

## Affected Locations

`src/resolver/package_json.rs:1538`

## Summary

The package exports resolver validated encoded path separators after percent-decoding the resolved path. Because `%2f`, `%2F`, `%5c`, and `%5C` become `/` or `\` before validation, the literal encoded-separator check could not detect them. An attacker-controlled export pattern subpath containing encoded separators could therefore bypass the package exports encoded-separator restriction.

## Provenance

Verified by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- The resolver enforces package exports for attacker-controlled imports.
- A malicious dependency package or malicious imported module can trigger resolution of an import specifier subpath containing encoded separators.
- The encoded subpath matches a package exports pattern and is substituted into the target path.

## Proof

`ESModule::resolve` calls `resolve_exports`, which can reach `resolve_imports_exports` for matching export patterns. `resolve_target` substitutes the attacker-controlled matched subpath into the export target and returns an `Exact` resolution.

Before the patch, `finalize` decoded `result.path` using `PercentEncoding::decode_into`, then searched the decoded buffer for literal `%2f`, `%2F`, `%5c`, and `%5C`. At that point encoded separators had already become `/` or `\`, so `found` remained empty and the resolved export was accepted.

The reproducer confirmed this behavior: encoded separators such as `%2f` and `%5c` were accepted after decoding. With encoded traversal components such as `%2e%2e%2f`, this propagated into filesystem resolution, where path normalization could resolve an existing file outside the intended exported package path.

## Why This Is A Real Bug

Package exports intentionally reject encoded `/` and `\` separators to prevent import specifiers from smuggling path structure through percent encoding. Checking for `%2f` and `%5c` only after decoding makes the policy ineffective because the evidence is destroyed before validation.

This is not only a specification mismatch. The reproduced flow showed that decoded separators can affect downstream filesystem resolution, including normalization of `..` segments, making the bypass security-relevant.

## Fix Requirement

Check `result.path` for encoded separators before percent decoding. The check must reject `%2f`, `%2F`, `%5c`, and `%5C`.

## Patch Rationale

The patch moves the existing encoded-separator validation ahead of `PercentEncoding::decode_into`. This preserves the original bytes long enough to detect forbidden encoded separators, then keeps the existing percent-decoding and directory-import checks unchanged.

The patch is minimal and targeted: it changes validation order without changing resolution semantics for paths that do not contain forbidden encoded separators.

## Residual Risk

None

## Patch

```diff
diff --git a/src/resolver/package_json.rs b/src/resolver/package_json.rs
index 234a2f26cc..c7b1d775e7 100644
--- a/src/resolver/package_json.rs
+++ b/src/resolver/package_json.rs
@@ -2416,6 +2416,25 @@ impl<'a> ESModule<'a> {
 
         // If resolved contains any percent encodings of "/" or "\" ("%2f" and "%5C"
         // respectively), then throw an Invalid Module Specifier error.
+        let mut found: &[u8] = b"";
+        if strings::contains(&result.path, INVALID_PERCENT_CHARS[0]) {
+            found = INVALID_PERCENT_CHARS[0];
+        } else if strings::contains(&result.path, INVALID_PERCENT_CHARS[1]) {
+            found = INVALID_PERCENT_CHARS[1];
+        } else if strings::contains(&result.path, INVALID_PERCENT_CHARS[2]) {
+            found = INVALID_PERCENT_CHARS[2];
+        } else if strings::contains(&result.path, INVALID_PERCENT_CHARS[3]) {
+            found = INVALID_PERCENT_CHARS[3];
+        }
+
+        if !found.is_empty() {
+            return Resolution {
+                status: Status::InvalidModuleSpecifier,
+                path: result.path,
+                debug: result.debug,
+            };
+        }
+
         // SAFETY: threadlocal UnsafeCell; finalize() does not recurse, so this is the unique
         // live `&mut` to resolved_path_buf_percent on this thread.
         let resolved_path_buf_percent: &mut PathBuffer =
@@ -2437,25 +2456,6 @@ impl<'a> ESModule<'a> {
 
         let resolved_path = &resolved_path_buf_percent.0[0..len as usize];
 
-        let mut found: &[u8] = b"";
-        if strings::contains(resolved_path, INVALID_PERCENT_CHARS[0]) {
-            found = INVALID_PERCENT_CHARS[0];
-        } else if strings::contains(resolved_path, INVALID_PERCENT_CHARS[1]) {
-            found = INVALID_PERCENT_CHARS[1];
-        } else if strings::contains(resolved_path, INVALID_PERCENT_CHARS[2]) {
-            found = INVALID_PERCENT_CHARS[2];
-        } else if strings::contains(resolved_path, INVALID_PERCENT_CHARS[3]) {
-            found = INVALID_PERCENT_CHARS[3];
-        }
-
-        if !found.is_empty() {
-            return Resolution {
-                status: Status::InvalidModuleSpecifier,
-                path: result.path,
-                debug: result.debug,
-            };
-        }
-
         // If resolved is a directory, throw an Unsupported Directory Import error.
         if strings::ends_with_any(resolved_path, b"/\\") {
             return Resolution {
```