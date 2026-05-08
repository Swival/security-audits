# RSA Private Key Created With Umask-Derived Permissions

## Classification

Information disclosure, medium severity.

## Affected Locations

`lib/libkeynote/keynote-keygen.c:322`

## Summary

The RSA private-key output path used `fopen(argv[4], "w")` to create the KeyNote private signing key file. `fopen` creates files according to the process umask, so a permissive umask such as `022` or `000` could create the private key as world-readable or group-readable. A lower-privileged local user with filesystem access could read the generated RSA private signing key and use it to sign KeyNote assertions.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The victim runs KeyNote key generation using the RSA branch.
- The victim provides a private-key file path instead of `-`.
- The victim's current umask allows group or world readability, such as `022` or `000`.
- A lower-privileged local attacker has directory traversal/read access to the generated file path.

## Proof

The RSA branch is reachable through `keygen` dispatch and selected when the requested algorithm resolves to RSA with PKCS#1 encoding.

Relevant flow:

- `keynote-main.c:66` dispatches `keygen` to `keynote_keygen`.
- `lib/libkeynote/keynote-keygen.c:268` selects the RSA branch.
- `lib/libkeynote/keynote-keygen.c:273` generates RSA private key material.
- `lib/libkeynote/keynote-keygen.c:309` encodes the key as `KEYNOTE_PRIVATE_KEY`.
- `lib/libkeynote/signature.c:1214` serializes that private key using `i2d_RSAPrivateKey`.
- `lib/libkeynote/keynote-keygen.c:324` previously wrote the private-key file using `fopen(argv[4], "w")`.

Because `fopen("w")` creates a new file with mode `0666 & ~umask`, a victim running with umask `022` could create a private key file with mode `0644`, and umask `000` could create it with mode `0666`.

## Why This Is A Real Bug

The file contains a KeyNote RSA private signing key, not public metadata. Its confidentiality is required to preserve signing authority. Creating it with permissions derived from a permissive umask exposes the key to local users who should not be able to sign assertions as the key owner.

This is not merely a hardening issue: the vulnerable operation directly writes secret key material to a file whose permissions can allow lower-privileged users to read it.

## Fix Requirement

Private key files must be created with owner-only permissions regardless of the caller's umask. Acceptable fixes include:

- Creating the file with `open(..., 0600)` and then wrapping it with `fdopen`.
- Applying `chmod` or `fchmod` to force mode `0600` before exposing the file.

## Patch Rationale

The patch replaces the RSA private-key `fopen(argv[4], "w")` path with:

- `open(argv[4], O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR)` to request owner-read/write permissions at creation.
- `fchmod(fd, S_IRUSR | S_IWUSR)` to force the final file mode to `0600`, including cases where an existing file is truncated.
- `fdopen(fd, "w")` to preserve the existing `FILE *`-based printing logic.

This ensures RSA private-key files are not left group-readable or world-readable due to a permissive umask.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/libkeynote/keynote-keygen.c b/lib/libkeynote/keynote-keygen.c
index edf013e..3087c55 100644
--- a/lib/libkeynote/keynote-keygen.c
+++ b/lib/libkeynote/keynote-keygen.c
@@ -99,7 +99,7 @@ keynote_keygen(int argc, char *argv[])
 {
     int begin = KEY_PRINT_OFFSET, prlen = KEY_PRINT_LENGTH;
     char *foo, *privalgname, seed[SEED_LEN];
-    int alg, enc, ienc, len = 0, counter;
+    int alg, enc, ienc, len = 0, counter, fd;
     struct keynote_deckey dc;
     unsigned long h;
     DSA *dsa;
@@ -321,10 +321,23 @@ keynote_keygen(int argc, char *argv[])
 	}
 	else
 	{
-	    fp = fopen(argv[4], "w");
+	    fd = open(argv[4], O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
+	    if (fd == -1)
+	    {
+		perror(argv[4]);
+		exit(1);
+	    }
+	    if (fchmod(fd, S_IRUSR | S_IWUSR) == -1)
+	    {
+		perror(argv[4]);
+		close(fd);
+		exit(1);
+	    }
+	    fp = fdopen(fd, "w");
 	    if (fp == NULL)
 	    {
 		perror(argv[4]);
+		close(fd);
 		exit(1);
 	    }
 	}
```