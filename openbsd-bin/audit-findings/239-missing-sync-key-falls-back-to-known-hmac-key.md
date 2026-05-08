# Missing Sync Key Falls Back To Known HMAC Key

## Classification

Authentication bypass, high severity. Confidence: certain.

## Affected Locations

`usr.sbin/dhcpd/sync.c:149`

## Summary

When DHCP sync is enabled and `DHCP_SYNC_KEY` is absent, `sync_init()` continues with `sync_key = ""`. Packet authentication later uses HMAC-SHA1 with `sync_key` and `strlen(sync_key)`, making the effective HMAC key the public empty string. A remote host on the DHCP sync network can forge authenticated sync lease packets and cause unauthorized lease insertion or supersession.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

## Preconditions

- DHCP sync is enabled.
- The `DHCP_SYNC_KEY` file is absent.
- The attacker can send packets to the DHCP sync UDP listener or multicast group.

## Proof

`sync_init()` reads `DHCP_SYNC_KEY` using `SHA1File(DHCP_SYNC_KEY, NULL)`. In the vulnerable code, if this fails with `errno == ENOENT`, initialization does not fail and instead assigns:

```c
sync_key = "";
```

In interface or multicast sync mode, `sync_init()` registers `sync_recv()` as the receive handler. Receive-side filtering only ignores packets from the daemon's own interface address.

`sync_recv()` authenticates packets by copying the supplied HMAC, zeroing `hdr->sh_hmac`, and computing:

```c
HMAC(EVP_sha1(), sync_key, strlen(sync_key), buf, len, hmac[1], &hmac_len);
```

With the missing-key fallback, this computes HMAC-SHA1 with a zero-length key. An attacker can therefore forge a valid packet by:

1. Constructing a DHCP sync packet containing `DHCP_SYNC_LEASE`.
2. Zeroing `sh_hmac`.
3. Computing HMAC-SHA1 over the packet using the empty key.
4. Writing the result into `sh_hmac`.
5. Sending the packet to the sync listener or multicast group.

If the HMAC matches, `sync_recv()` accepts the packet. Accepted `DHCP_SYNC_LEASE` data is copied into a lease structure and applied through `enter_lease()`/`write_leases()` or `supersede_lease()`, enabling unauthorized lease insertion or supersession.

## Why This Is A Real Bug

The missing-key path turns authentication from secret-based HMAC verification into verification with a known public key. Because HMAC with an empty key is deterministic and computable by anyone, the receiver cannot distinguish legitimate sync peers from forged remote packets. The accepted packet directly mutates the DHCP lease database, so the impact is not limited to logging or packet parsing.

## Fix Requirement

DHCP sync initialization must fail if `DHCP_SYNC_KEY` cannot be opened, including when the file is absent. The daemon must not enter sync receive mode with an empty, default, or otherwise public authentication key.

## Patch Rationale

The patch removes the special `ENOENT` fallback and treats all `SHA1File()` failures as fatal:

```diff
 sync_key = SHA1File(DHCP_SYNC_KEY, NULL);
 if (sync_key == NULL) {
-	if (errno != ENOENT) {
-		log_warn("failed to open sync key");
-		return (-1);
-	}
-	/* Use empty key by default */
-	sync_key = "";
+	log_warn("failed to open sync key");
+	return (-1);
 }
```

This ensures DHCP sync cannot start unless a key file is present and readable. As a result, `sync_recv()` and `sync_lease()` no longer operate with the known empty-string HMAC key.

## Residual Risk

None

## Patch

`239-missing-sync-key-falls-back-to-known-hmac-key.patch`

```diff
diff --git a/usr.sbin/dhcpd/sync.c b/usr.sbin/dhcpd/sync.c
index bdaf6f7..03ed4a7 100644
--- a/usr.sbin/dhcpd/sync.c
+++ b/usr.sbin/dhcpd/sync.c
@@ -143,12 +143,8 @@ sync_init(const char *iface, const char *baddr, u_short port)
 
 	sync_key = SHA1File(DHCP_SYNC_KEY, NULL);
 	if (sync_key == NULL) {
-		if (errno != ENOENT) {
-			log_warn("failed to open sync key");
-			return (-1);
-		}
-		/* Use empty key by default */
-		sync_key = "";
+		log_warn("failed to open sync key");
+		return (-1);
 	}
 
 	syncfd = socket(AF_INET, SOCK_DGRAM, 0);
```