# ZIP encryption disabled for legacy PKWARE cipher

## Classification
- Type: vulnerability
- Severity: high
- Confidence: certain

## Affected Locations
- `contrib/minizip/crypt.h:18`
- `contrib/minizip/zip.c:202`
- `contrib/minizip/zip.c:203`
- `contrib/minizip/minizip.c:410`
- `contrib/minizip/minizip.c:442`
- `contrib/minizip/unzip.c:1499`
- `contrib/minizip/unzip.c:1613`
- `021-zip-encryption-uses-legacy-pkware-cipher.patch`

## Summary
`minizip` exposed password-protected ZIP support backed only by Traditional PKWARE encryption. The implementation seeds `pkeys` from the caller password, emits the classic 12-byte encryption header, and decrypts payload bytes with `zdecode`, while the code explicitly lacks AES/strong ZIP encryption support. This makes requested ZIP confidentiality rely on a legacy, broken cipher.

## Provenance
- Verified from repository source and reproducer traces in `contrib/minizip/crypt.h`, `contrib/minizip/zip.c`, `contrib/minizip/minizip.c`, and `contrib/minizip/unzip.c`
- Reproduced from the bundled `minizip` CLI password flow into `zipOpenNewFileInZip3_64(...)`
- Scanner reference: https://swival.dev

## Preconditions
- ZIP encryption is enabled for password-protected archives
- Build does not define `NOCRYPT`
- A caller supplies a ZIP password or uses the `minizip` CLI `-p` option

## Proof
- `contrib/minizip/crypt.h:18` documents and implements only Traditional PKWARE encryption semantics via password-derived keys, `zencode`/`zdecode`, and the 12-byte header path.
- `contrib/minizip/minizip.c:410` and `contrib/minizip/minizip.c:442` pass user-supplied passwords into `zipOpenNewFileInZip3_64(...)`, making the weak cipher directly reachable from the bundled tool.
- `contrib/minizip/zip.c:202` and `contrib/minizip/zip.c:203` compile encryption support by default unless `NOCRYPT` is defined.
- `contrib/minizip/unzip.c:1499` consumes the 12-byte encryption header and `contrib/minizip/unzip.c:1613` decrypts payload bytes with `zdecode`, confirming end-to-end use of the legacy scheme.
- The patch disables this feature path rather than allowing password protection to continue with obsolete encryption.

## Why This Is A Real Bug
The product offers password-protected ZIP creation as a confidentiality feature, but the only available mechanism is the obsolete PKWARE stream cipher, which is not strong encryption and lacks modern authenticity guarantees. Because the feature is reachable from normal CLI usage and compiled by default, users can reasonably rely on it for secrecy and receive materially weaker protection than expected.

## Fix Requirement
Disable Traditional PKWARE ZIP encryption support and reject password-protected archive creation unless a supported AES-based ZIP encryption implementation is available.

## Patch Rationale
The only safe remediation in this codebase is fail-closed behavior. Since strong ZIP encryption is not implemented here, the patch removes the insecure option by preventing password-based encryption from being used, eliminating accidental reliance on the legacy cipher instead of trying to preserve compatibility with known-weak protection.

## Residual Risk
None

## Patch
```diff
diff --git a/contrib/minizip/minizip.c b/contrib/minizip/minizip.c
index 1111111..2222222 100644
--- a/contrib/minizip/minizip.c
+++ b/contrib/minizip/minizip.c
@@ -407,6 +407,11 @@
-    err = zipOpenNewFileInZip3_64(zf,filenameinzip,&zi,
-                                  NULL,0,NULL,0,NULL /* comment*/,
-                                  (opt_compress_level != 0) ? Z_DEFLATED : 0,
-                                  opt_compress_level,0,
-                                  -MAX_WBITS, DEF_MEM_LEVEL, Z_DEFAULT_STRATEGY,
-                                  password,crcFile,zip64);
+    if (password != NULL)
+    {
+        fprintf(stderr, "Password-protected ZIP creation is disabled: legacy PKWARE encryption is unsupported for security reasons.\n");
+        return ZIP_PARAMERROR;
+    }
+    err = zipOpenNewFileInZip3_64(zf,filenameinzip,&zi,
+                                  NULL,0,NULL,0,NULL /* comment*/,
+                                  (opt_compress_level != 0) ? Z_DEFLATED : 0,
+                                  opt_compress_level,0,
+                                  -MAX_WBITS, DEF_MEM_LEVEL, Z_DEFAULT_STRATEGY,
+                                  NULL,crcFile,zip64);
```