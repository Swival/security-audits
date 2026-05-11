# SearchPath CA Bundle Lookup Trusts Attacker-Writable Directories

## Classification

Security control failure, high severity.

## Affected Locations

`src/tool_doswin.c:565` (`FindWin32CACert`)

## Summary

On Windows builds using a non-Schannel TLS backend with unsafe CA search enabled, curl automatically discovers a default CA bundle through `SearchPath(NULL, ...)`. That search order includes the current working directory and `%PATH%`, allowing a lower-privileged local attacker to plant `curl-ca-bundle.crt` in an attacker-writable working directory and make curl use it as TLS trust anchors.

## Provenance

Verified from the supplied source, reproduced behavior, and patch.

Reported by Swival.dev Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Windows curl build.
- Non-Schannel TLS backend selected.
- Unsafe CA bundle search compiled in.
- No explicit `--cacert` or `--capath`.
- No overriding CA-related environment variables.
- Victim runs curl from an attacker-writable current directory containing `curl-ca-bundle.crt`.

## Proof

`FindWin32CACert` calls:

```c
res_len = SearchPath(NULL, bundle_file, NULL, MAX_PATH, buf, &ptr);
```

With `NULL` as the search path, Windows searches locations that include the application directory, current working directory, system directories, Windows directory, and `%PATH%`.

On success, the discovered path is assigned to curl configuration:

```c
config->cacert = curlx_convert_tchar_to_UTF8(buf);
```

The reproduced data confirms this value is propagated into `CURLOPT_CAINFO` through `src/config2setopts.c:292`, and TLS backends load it as CA trust material, including `lib/vtls/openssl.c:3025`, `lib/vtls/gtls.c:507`, and `lib/vtls/mbedtls.c:539`.

Therefore, if an attacker-controlled current directory contains `curl-ca-bundle.crt`, curl can select that attacker-controlled file as the CA bundle for TLS server authentication.

## Why This Is A Real Bug

CA bundle discovery is part of TLS certificate verification. Trusting a file selected from the current working directory or `%PATH%` lets local filesystem placement influence the root CAs trusted by curl.

A lower-privileged local attacker who can plant `curl-ca-bundle.crt` in the victim’s working directory can cause curl to trust certificates chaining to the attacker’s root CA. If the attacker can also present such a certificate for the requested host, this enables TLS impersonation or MITM despite certificate verification being enabled.

## Fix Requirement

The automatic CA bundle lookup must not search attacker-writable or ambient process-controlled directories such as the current working directory or `%PATH%`.

It should search only trusted locations, such as the curl executable directory or explicitly configured directories.

## Patch Rationale

The patch replaces `SearchPath(NULL, ...)` with a constrained search rooted at the curl tool directory:

```c
res_len = GetModuleFileName(NULL, path, MAX_PATH);
```

It then strips the executable filename, leaving only the application directory, and calls:

```c
res_len = SearchPath(path, bundle_file, NULL, MAX_PATH, buf, &ptr);
```

This preserves automatic discovery of a CA bundle colocated with the curl executable while removing current-directory and `%PATH%` influence from trust-anchor selection.

The patch also requires successful, non-truncated paths by checking `res_len > 0 && res_len < MAX_PATH` before using returned paths.

## Residual Risk

None

## Patch

```diff
diff --git a/src/tool_doswin.c b/src/tool_doswin.c
index 4b2a2a34b3..a02978c7e5 100644
--- a/src/tool_doswin.c
+++ b/src/tool_doswin.c
@@ -539,35 +539,33 @@ SANITIZEcode sanitize_file_name(char ** const sanitized, const char *file_name,
  * setting CA location for Schannel only when explicitly specified by the user
  * via CURLOPT_CAINFO / --cacert.
  *
- * Function to find CACert bundle on a Win32 platform using SearchPath.
- * (SearchPath is already declared via inclusions done in setup header file)
- * (Use the ASCII version instead of the Unicode one!)
- * The order of the directories it searches is:
- *  1. application's directory
- *  2. current working directory
- *  3. Windows System directory (e.g. C:\Windows\System32)
- *  4. Windows Directory (e.g. C:\Windows)
- *  5. all directories along %PATH%
- *
- * For WinXP and later search order actually depends on registry value:
- * HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\SafeProcessSearchMode
+ * Find the CACert bundle in the curl tool directory only.
  */
 CURLcode FindWin32CACert(struct OperationConfig *config,
                          const TCHAR *bundle_file)
 {
   CURLcode result = CURLE_OK;
   DWORD res_len;
+  TCHAR path[MAX_PATH];
   TCHAR buf[MAX_PATH];
   TCHAR *ptr = NULL;
 
   buf[0] = TEXT('\0');
 
-  res_len = SearchPath(NULL, bundle_file, NULL, MAX_PATH, buf, &ptr);
-  if(res_len > 0) {
-    curlx_free(config->cacert);
-    config->cacert = curlx_convert_tchar_to_UTF8(buf);
-    if(!config->cacert)
-      result = CURLE_OUT_OF_MEMORY;
+  res_len = GetModuleFileName(NULL, path, MAX_PATH);
+  if(res_len > 0 && res_len < MAX_PATH) {
+    ptr = _tcsrchr(path, TEXT('\\'));
+    if(ptr) {
+      *ptr = TEXT('\0');
+      ptr = NULL;
+      res_len = SearchPath(path, bundle_file, NULL, MAX_PATH, buf, &ptr);
+      if(res_len > 0 && res_len < MAX_PATH) {
+        curlx_free(config->cacert);
+        config->cacert = curlx_convert_tchar_to_UTF8(buf);
+        if(!config->cacert)
+          result = CURLE_OUT_OF_MEMORY;
+      }
+    }
   }
 
   return result;
```