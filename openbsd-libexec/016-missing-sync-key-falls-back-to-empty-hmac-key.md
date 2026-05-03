# Missing Sync Key Falls Back To Empty HMAC Key

## Classification

High severity authentication bypass.

## Affected Locations

`spamd/sync.c:152`

## Summary

When spamd sync is enabled and `SPAM_SYNC_KEY` is absent, `sync_init()` falls back to `sync_key = ""`. `sync_recv()` then authenticates inbound UDP sync packets with `HMAC(EVP_sha1(), sync_key, strlen(sync_key), ...)`, making the effective HMAC key public and zero length. A remote sender who can reach the sync UDP port can compute the same empty-key HMAC and inject accepted greylist, whitelist, or trapped-address updates.

## Provenance

Verified and patched from the provided source and reproducer evidence.

Scanner provenance: [Swival Security Scanner](https://swival.dev)

Confidence: certain.

## Preconditions

- Sync is enabled.
- `SPAM_SYNC_KEY` file is absent.
- Attacker can send UDP sync datagrams to the spamd sync listener.

## Proof

`sync_init()` loads the sync key with `SHA1File(SPAM_SYNC_KEY, NULL)`. If that call fails with `errno == ENOENT`, the old code explicitly takes the documented missing-file path and assigns:

```c
sync_key = "";
```

`sync_recv()` copies the packet HMAC, zeroes the header HMAC field, and verifies the packet with:

```c
HMAC(EVP_sha1(), sync_key, strlen(sync_key), buf, len, hmac[1], &hmac_len);
```

With the missing-key path, `strlen(sync_key)` is zero. Therefore authentication uses an empty HMAC key. An attacker can compute `HMAC-SHA1(empty_key, packet_with_zeroed_hmac_field)`, place it in `hdr->sh_hmac`, and pass the check.

Once accepted, packets reach the update handlers:

- `SPAM_SYNC_GREY` writes greylist sync data to the greylister pipe.
- `SPAM_SYNC_WHITE` writes `WHITE:<ip>:<source>:<expire>`.
- `SPAM_SYNC_TRAPPED` writes `TRAP:<ip>:<source>:<expire>`.

The reproduced path confirms those lines are parsed by `greyreader()` and persisted through `twread()` / `twupdate()` into `/var/db/spamd`.

## Why This Is A Real Bug

The sync HMAC is the only authentication barrier before remote state updates are accepted. Falling back to an empty key converts a secret-key MAC into a publicly computable checksum. This allows unauthenticated remote sync packet senders to forge valid packets and modify spamd greylist, whitelist, or trap state when sync is enabled and the key file is missing.

## Fix Requirement

Sync initialization must fail closed if `SPAM_SYNC_KEY` is missing or empty. It must not substitute an empty key or otherwise allow HMAC verification with a zero-length shared secret.

## Patch Rationale

The patch removes the missing-file fallback and validates the key file before use:

- Adds `#include <sys/stat.h>`.
- Calls `stat(SPAM_SYNC_KEY, &st)` before `SHA1File()`.
- Fails `sync_init()` if the key file cannot be opened, including `ENOENT`.
- Fails `sync_init()` if `st.st_size == 0`.
- Keeps the existing `SHA1File()` load path for valid non-empty key files.

This makes sync fail closed instead of silently authenticating with an empty HMAC key.

## Residual Risk

None

## Patch

```diff
diff --git a/spamd/sync.c b/spamd/sync.c
index 5daca75..cc2425c 100644
--- a/spamd/sync.c
+++ b/spamd/sync.c
@@ -17,6 +17,7 @@
  */
 
 #include <sys/socket.h>
+#include <sys/stat.h>
 #include <sys/uio.h>
 #include <sys/ioctl.h>
 #include <sys/queue.h>
@@ -121,6 +122,7 @@ sync_init(const char *iface, const char *baddr, u_short port)
 	struct ifreq ifr;
 	struct ip_mreq mreq;
 	struct sockaddr_in *addr;
+	struct stat st;
 	char ifnam[IFNAMSIZ], *ttlstr;
 	const char *errstr;
 	struct in_addr ina;
@@ -142,15 +144,19 @@ sync_init(const char *iface, const char *baddr, u_short port)
 		}
 	}
 
-	sync_key = SHA1File(SPAM_SYNC_KEY, NULL);
-	if (sync_key == NULL) {
-		if (errno != ENOENT) {
-			fprintf(stderr, "failed to open sync key: %s\n",
-			    strerror(errno));
-			return (-1);
-		}
-		/* Use empty key by default */
-		sync_key = "";
+	if (stat(SPAM_SYNC_KEY, &st) == -1) {
+		fprintf(stderr, "failed to open sync key: %s\n",
+		    strerror(errno));
+		return (-1);
+	}
+	if (st.st_size == 0) {
+		fprintf(stderr, "failed to open sync key: empty key\n");
+		return (-1);
+	}
+	if ((sync_key = SHA1File(SPAM_SYNC_KEY, NULL)) == NULL) {
+		fprintf(stderr, "failed to open sync key: %s\n",
+		    strerror(errno));
+		return (-1);
 	}
 
 	syncfd = socket(AF_INET, SOCK_DGRAM, 0);
```