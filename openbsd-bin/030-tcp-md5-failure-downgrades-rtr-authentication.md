# TCP MD5 failure downgrades RTR authentication

## Classification

Authentication bypass, medium severity. Confidence: certain.

## Affected Locations

`usr.sbin/bgpd/bgpd.c:1402`

## Summary

`bgpd_rtr_conn_setup()` configures TCP MD5 for RTR sockets but treats `tcp_md5_set()` failure as non-fatal. The same socket is then bound, connected, and passed to the RTR engine, allowing an RTR session to proceed without the configured TCP MD5 authentication.

## Provenance

Verified by reproduced code-path analysis. Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- An RTR peer has TCP MD5 configured.
- `tcp_md5_set(ce->fd, &r->auth, &r->remote_addr)` returns `-1`.
- A remote endpoint at the configured RTR address can accept or complete the TCP connection.

## Proof

In `bgpd_rtr_conn_setup()`, the socket is created and configured, then TCP MD5 setup is attempted:

```c
if (tcp_md5_set(ce->fd, &r->auth, &r->remote_addr) == -1)
	log_warn("rtr %s: setting md5sig", r->descr);
```

The failure is only logged. Execution continues to `bind()` and `connect()`. If `connect()` succeeds immediately, the same file descriptor is sent to the RTR engine via `IMSG_SOCKET_SETUP`. If `connect()` is asynchronous, `bgpd_rtr_conn_setup_done()` later checks `SO_ERROR == 0` and then sends the same file descriptor to the RTR engine.

The RTR engine receives and opens the session using that socket, and the reproduced path found no later RTR authentication check. `rtr_config_msg` only carries `descr` and `min_version`, so no downstream component can re-enforce the configured TCP MD5 requirement.

## Why This Is A Real Bug

TCP MD5 is an explicit authentication control for the RTR peer. When local MD5 setup fails, continuing with the connection converts a configured authenticated RTR transport into an unauthenticated TCP session. A malicious RTR cache or MITM at the configured endpoint can then complete the session and provide RTR data despite authentication being configured.

This is a fail-open authentication downgrade.

## Fix Requirement

Failure to apply TCP MD5 to an RTR socket must abort the connection attempt. The unauthenticated socket must not be connected or passed to the RTR engine.

## Patch Rationale

The patch changes `tcp_md5_set()` failure handling from log-and-continue to log-and-fail. This preserves the existing cleanup path, closes the socket, frees the connection element, and prevents unauthenticated RTR connection establishment.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/bgpd/bgpd.c b/usr.sbin/bgpd/bgpd.c
index f1dc136..32b6771 100644
--- a/usr.sbin/bgpd/bgpd.c
+++ b/usr.sbin/bgpd/bgpd.c
@@ -1409,8 +1409,10 @@ bgpd_rtr_conn_setup(struct rtr_config *r)
 		goto fail;
 	}
 
-	if (tcp_md5_set(ce->fd, &r->auth, &r->remote_addr) == -1)
+	if (tcp_md5_set(ce->fd, &r->auth, &r->remote_addr) == -1) {
 		log_warn("rtr %s: setting md5sig", r->descr);
+		goto fail;
+	}
 
 	if ((sa = addr2sa(&r->local_addr, 0, &len)) != NULL) {
 		if (bind(ce->fd, sa, len) == -1) {
```