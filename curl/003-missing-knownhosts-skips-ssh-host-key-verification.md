# Missing knownhosts skips SSH host key verification

## Classification

Security control failure, high severity, certain confidence.

## Affected Locations

`lib/vssh/libssh.c:289` (`myssh_is_known` fall-through to `rc = SSH_OK`)

## Summary

The libssh SSH host key verifier accepts a server key when neither an MD5 host key pin nor an explicit knownhosts path is configured. This causes SCP/SFTP connections using the libssh backend to proceed to authentication without host key verification, allowing an attacker-controlled SSH server to impersonate the intended server.

## Provenance

Verified from the supplied source, reproducer summary, and patch.

Originally identified by Swival.dev Security Scanner: https://swival.dev

## Preconditions

A vulnerable connection requires:

- libcurl built/used with the libssh backend.
- SCP or SFTP connection setup reaches `myssh_is_known`.
- No `CURLOPT_SSH_HOST_PUBLIC_KEY_MD5` value is configured.
- No `CURLOPT_SSH_KNOWNHOSTS` path is configured.
- A malicious SSH server can intercept or receive the client connection.

## Proof

`myssh_is_known` is the libssh backend host key verification gate before authentication.

- `lib/vssh/libssh.c:142` verifies only `STRING_SSH_HOST_PUBLIC_KEY_MD5` when configured.
- `lib/vssh/libssh.c:171` performs known_hosts validation only when `STRING_SSH_KNOWNHOSTS` is configured.
- The `data->set.ssh_keyfunc` callback is consulted only inside the `STRING_SSH_KNOWNHOSTS` branch, so a caller that sets only the callback is also unprotected.
- When neither option is set, all verification branches are skipped.
- Control reaches `rc = SSH_OK` at `lib/vssh/libssh.c:289`.
- `myssh_statemachine` calls `myssh_is_known` in state `SSH_HOSTKEY`.
- On `SSH_OK`, it transitions to `SSH_AUTHLIST`, so authentication proceeds against an unverified server key.

An attacker running a malicious SSH server can present any host key and be accepted before credentials or file contents are exchanged.

## Why This Is A Real Bug

SSH host key verification is the control that prevents server impersonation. The function comment says that when no MD5 pin or callback path is used, the connection should only be accepted if the key is present in known hosts. The implementation instead fails open when `STRING_SSH_KNOWNHOSTS` is absent, returning `SSH_OK` without any equivalent trust decision.

This is exploitable in the stated configuration because authentication and data transfer occur after `SSH_HOSTKEY`, and the state machine treats `SSH_OK` as verified.

## Fix Requirement

Reject the connection when no host key verification mechanism is configured.

Specifically, if `STRING_SSH_HOST_PUBLIC_KEY_MD5` is absent and `STRING_SSH_KNOWNHOSTS` is absent, `myssh_is_known` must return `SSH_ERROR` so the caller maps the failure to `CURLE_PEER_FAILED_VERIFICATION`.

## Patch Rationale

The patch adds an `else` branch paired with the knownhosts check:

```c
else {
  rc = SSH_ERROR;
  goto cleanup;
}
```

This converts the previously implicit success path into an explicit verification failure when neither accepted verifier is configured. Existing successful paths remain unchanged:

- Matching MD5 host key pin still returns `SSH_OK`.
- Knownhosts match still returns `SSH_OK`.
- Knownhosts callback acceptance still returns `SSH_OK`.
- Knownhosts mismatch, missing entry without callback acceptance, and unsupported key types still fail.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/vssh/libssh.c b/lib/vssh/libssh.c
index c6a6e0cfdf..d129ff2a72 100644
--- a/lib/vssh/libssh.c
+++ b/lib/vssh/libssh.c
@@ -286,6 +286,10 @@ static int myssh_is_known(struct Curl_easy *data, struct ssh_conn *sshc)
       }
     }
   }
+  else {
+    rc = SSH_ERROR;
+    goto cleanup;
+  }
   rc = SSH_OK;
 
 cleanup:
```