# Certificate Private-Key Match Dereferences Null Key

## Classification

Denial of service, medium severity. Confidence: certain.

## Affected Locations

`sshconnect2.c:1272` (null deref in `identity_sign` post-success)

`sshconnect2.c:1360`-`sshconnect2.c:1362` (origin: filename-match selection of identity with NULL public key)

`sshconnect2.c:1436` (null deref in `sign_and_send_pubkey` SHA-2 fallback)

## Summary

A malicious SSH server can crash the SSH client during public-key authentication when the client has a certificate identity and a filename-matched private-key identity whose public key was not loaded. The certificate signing path may select that private-key identity even though `sign_id->key == NULL`, then later dereference `sign_id->key->flags`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched from the supplied source and reproducer evidence.

## Preconditions

- The client has a certificate identity.
- The client also has a matching private-key filename identity.
- The matching private-key identity has no loaded public key, so its `Identity.key` field is `NULL`.
- A malicious SSH server sends `USERAUTH_PK_OK` for the offered certificate.

## Proof

`input_userauth_pk_ok` accepts `USERAUTH_PK_OK` for a previously offered key, finds the matching certificate `Identity`, and calls `sign_and_send_pubkey`.

For certificate identities, `sign_and_send_pubkey` searches for a private identity to perform signing. If no exact public-key match exists, it permits filename matches for non-agent/non-PKCS#11 identities whose public key was not loaded:

```c
if (private_id->key == NULL &&
    id_filename_matches(id, private_id)) {
        sign_id = private_id;
        break;
}
```

This assigns a filename-matched private-key identity with `sign_id->key == NULL`.

The reproduced path confirms this state is practical when the private key can be loaded later from disk but no public key was loaded initially, for example an old PEM/PKCS8 private key without a `.pub` file. `identity_sign` then loads the private key from disk and can sign successfully, while the selected `Identity` still has `id->key == NULL`.

There are two reachable null dereferences once that selection has happened:

1. After a successful `sshkey_sign` inside `identity_sign`, the post-sign sanity check unconditionally reads `id->key->flags`:

```c
if ((id->key->flags & SSHKEY_FLAG_EXT) != 0 &&
    (r = sshkey_check_sigtype(*sigp, *lenp, alg)) != 0) {
```

2. The `SSH_ERR_SIGN_ALG_UNSUPPORTED` fallback branch in `sign_and_send_pubkey`:

```c
else if ((sign_id->key->flags & SSHKEY_FLAG_EXT) != 0)
        loc = "token ";
```

Without a `NULL` guard, both read `flags` through a null pointer.

## Why This Is A Real Bug

The server controls whether to send `USERAUTH_PK_OK` for the offered certificate. Once sent, the client enters the certificate signing path and may select a filename-matched private-key identity with no loaded public key. The source explicitly allows `private_id->key == NULL` in this matching path, and later code reads `sign_id->key->flags` (or `id->key->flags` inside `identity_sign`) without proving the pointer is non-null. The impact is termination of the SSH client process during authentication, which is a remote peer-triggered denial of service for clients with the affected identity layout.

## Fix Requirement

Do not dereference the selected identity's `key` field unless it is known to be non-null. Both `identity_sign` and the `sign_and_send_pubkey` fallback logging path must handle filename-matched private-key identities whose public key was not loaded.

## Patch Rationale

The patch adds explicit `key != NULL` guards at both unsafe accesses:

1. In `identity_sign`, before reading `id->key->flags` after a successful sign. When the public key was never loaded, the key cannot be PKCS#11/SK-backed, so skipping the SK sigtype check is correct.
2. In `sign_and_send_pubkey`, before reading `sign_id->key->flags` in the SHA-2 fallback branch.

This preserves existing behavior for agent and token-backed identities with loaded keys while preventing the null dereferences for filename-matched private-key identities.

## Residual Risk

None

## Patch

```diff
diff --git a/sshconnect2.c b/sshconnect2.c
index f34ceb7..4816f67 100644
--- a/sshconnect2.c
+++ b/sshconnect2.c
@@ -1269,7 +1269,8 @@ identity_sign(struct identity *id, u_char **sigp, size_t *lenp,
 	 * PKCS#11 tokens may not support all signature algorithms,
 	 * so check what we get back.
 	 */
-	if ((id->key->flags & SSHKEY_FLAG_EXT) != 0 &&
+	if (id->key != NULL &&
+	    (id->key->flags & SSHKEY_FLAG_EXT) != 0 &&
 	    (r = sshkey_check_sigtype(*sigp, *lenp, alg)) != 0) {
 		debug_fr(r, "sshkey_check_sigtype");
 		goto out;
@@ -1433,7 +1434,8 @@ sign_and_send_pubkey(struct ssh *ssh, Identity *id)
 		    !fallback_sigtype) {
 			if (sign_id->agent_fd != -1)
 				loc = "agent ";
-			else if ((sign_id->key->flags & SSHKEY_FLAG_EXT) != 0)
+			else if (sign_id->key != NULL &&
+			    (sign_id->key->flags & SSHKEY_FLAG_EXT) != 0)
 				loc = "token ";
 			logit("%skey %s %s returned incorrect signature type",
 			    loc, sshkey_type(id->key), fp);
```