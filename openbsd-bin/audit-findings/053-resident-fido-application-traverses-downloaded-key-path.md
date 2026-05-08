# Resident FIDO Application Path Traversal

## Classification

Path traversal, medium severity, confirmed with reproduction and patched.

## Affected Locations

`usr.bin/ssh/ssh-keygen.c:1951`

Primary affected implementation location after source alignment: `usr.bin/ssh/ssh-keygen.c:3061`

Related sinks:
`usr.bin/ssh/ssh-keygen.c:3132`
`usr.bin/ssh/ssh-keygen.c:3145`
`usr.bin/ssh/ssh-keygen.c:3160`
`usr.bin/ssh/sshbuf-io.c:103`
`usr.bin/ssh/authfile.c:484`

## Summary

`ssh-keygen -K` downloads resident FIDO keys and builds output filenames from authenticator-controlled `key->sk_application`. The previous `sk_suffix()` logic stripped only `ssh://` or `ssh:` prefixes and returned the remaining application string unchanged. If the application contained `/`, `..`, or `\`, that string reached private and public key output paths, allowing filesystem traversal during key export.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

User runs `ssh-keygen -K` with an attacker-controlled or malicious FIDO authenticator.

## Proof

`do_download_sk()` obtains each resident key and calls:

```c
ext = sk_suffix(key->sk_application,
    srks[i]->user_id, srks[i]->user_id_len);
xasprintf(&path, "id_%s_rk%s%s",
    key->type == KEY_ECDSA_SK ? "ecdsa_sk" : "ed25519_sk",
    *ext == '\0' ? "" : "_", ext);
```

The generated `path` is then used for writes:

```c
sshkey_save_private(key, path, ...)
sshkey_save_public(key, pubpath, ...)
```

Private key saving reaches `sshbuf_write_file()`, which calls:

```c
open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644)
```

Public key saving reaches equivalent plain-path file creation in `authfile.c`.

Concrete reproduced trigger: a malicious authenticator returns an ED25519-SK resident key with application `ssh:x/../../target` and an all-zero user id. With a current-directory entry `id_ed25519_sk_rk_x` that is a directory, `ssh-keygen -K` writes the private key to:

```text
id_ed25519_sk_rk_x/../../target
```

and writes the public key to the corresponding `.pub` path.

## Why This Is A Real Bug

The attacker controls the resident key application string through the authenticator. Before the patch, `sk_suffix()` sanitized the user id only when it contained `/`, `..`, or `\`; it did not apply the same safety rule to the application string. Because `do_download_sk()` concatenates the returned suffix directly into a filesystem path, path separators and parent-directory components in the application string alter the destination path. The sinks use ordinary `open(..., O_CREAT | O_TRUNC, ...)`, so the behavior can create or clobber files in the victim user's context.

## Fix Requirement

Reject or encode unsafe authenticator-supplied application strings before they are used in generated filenames. Unsafe strings include path separators, parent-directory components, and backslashes.

## Patch Rationale

The patch applies the existing filename-safety policy used for resident key user ids to the application-derived suffix. After stripping an optional `ssh://` or `ssh:` prefix, `sk_suffix()` now checks the application suffix for `/`, `..`, or `\`. If any are present, it hex-encodes the entire suffix before path construction. This preserves deterministic filenames while ensuring attacker-controlled path metacharacters cannot affect filesystem traversal.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/ssh/ssh-keygen.c b/usr.bin/ssh/ssh-keygen.c
index 25ee558..8c1af54 100644
--- a/usr.bin/ssh/ssh-keygen.c
+++ b/usr.bin/ssh/ssh-keygen.c
@@ -3061,6 +3061,12 @@ sk_suffix(const char *application, const uint8_t *user, size_t userlen)
 		ret =  xstrdup(p);
 	else
 		ret = xstrdup(application);
+	if (strchr(ret, '/') != NULL || strstr(ret, "..") != NULL ||
+	    strchr(ret, '\\') != NULL) {
+		cp = tohex(ret, strlen(ret));
+		free(ret);
+		ret = cp;
+	}
 
 	/* Count trailing zeros in user */
 	for (i = 0; i < userlen; i++) {
```