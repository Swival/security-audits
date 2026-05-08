# PFKEY failure downgrades RTR authentication

## Classification

Authentication bypass, medium severity.

## Affected Locations

`usr.sbin/bgpd/bgpd.c:1373`

## Summary

`bgpd_rtr_conn_setup()` attempted to establish PFKEY state for an authenticated RTR cache connection, but treated PFKEY setup failure as non-fatal. The function continued to create and connect a TCP socket, then passed the connected descriptor to the RTR engine. As a result, a configured RTR cache requiring transport authentication could still receive an unauthenticated RTR TCP session after local PFKEY setup failed.

## Provenance

Verified from supplied source, reproduced behavior, and patch evidence.

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- An RTR cache is configured.
- The RTR cache configuration requires authentication backed by PFKEY state.
- `pfkey_establish(&ce->auth_state, &r->auth, &r->local_addr, &r->remote_addr)` fails during RTR connection setup.
- A malicious or compromised RTR cache is reachable at the configured address.

## Proof

In `bgpd_rtr_conn_setup()`, the affected code calls `pfkey_establish()` before creating and connecting the RTR TCP socket:

```c
if (pfkey_establish(&ce->auth_state, &r->auth,
    &r->local_addr, &r->remote_addr) == -1)
        log_warnx("rtr %s: pfkey setup failed", r->descr);
```

Because the failure path only logs, execution continues to:

- assign the RTR ID and create a TCP socket;
- set TCP/IP options;
- call `tcp_md5_set()` and also only log on failure;
- bind and connect to `r->remote_addr`;
- send the connected file descriptor to the RTR engine with `IMSG_SOCKET_SETUP`.

The reproduced flow confirms that after this downgrade, the RTR engine accepts the fd, opens the session, sends RTR queries, reads RTR PDUs, and merges received ROA/ASPA data into route-validation state.

## Why This Is A Real Bug

Authentication failure is not enforced as a connection failure. The configured security property is that the RTR transport must be authenticated through PFKEY state and TCP MD5 where applicable. Continuing after `pfkey_establish()` or `tcp_md5_set()` failure creates a plain or improperly protected TCP RTR session to the configured cache. A malicious RTR cache at that address can then feed unauthenticated route-validation data into bgpd, bypassing the intended transport authentication.

## Fix Requirement

Abort RTR connection setup when authentication setup fails.

Specifically:

- If `pfkey_establish()` fails, do not create or connect the socket.
- If `tcp_md5_set()` fails, close the socket and discard the connection state.
- Do not send `IMSG_SOCKET_SETUP` to the RTR engine unless authentication setup succeeded.

## Patch Rationale

The patch makes authentication setup failures fatal for the current RTR connection attempt.

For PFKEY failure, it logs the existing warning, frees the allocated connection element, and returns before socket creation:

```c
if (pfkey_establish(&ce->auth_state, &r->auth,
    &r->local_addr, &r->remote_addr) == -1) {
        log_warnx("rtr %s: pfkey setup failed", r->descr);
        free(ce);
        return;
}
```

For TCP MD5 setup failure, it logs the existing warning and jumps to the existing cleanup path:

```c
if (tcp_md5_set(ce->fd, &r->auth, &r->remote_addr) == -1) {
        log_warn("rtr %s: setting md5sig", r->descr);
        goto fail;
}
```

The existing `fail` path closes `ce->fd` when needed and frees `ce`, preventing the RTR engine from receiving a connected unauthenticated descriptor.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/bgpd/bgpd.c b/usr.sbin/bgpd/bgpd.c
index f1dc136..b536b81 100644
--- a/usr.sbin/bgpd/bgpd.c
+++ b/usr.sbin/bgpd/bgpd.c
@@ -1375,8 +1375,11 @@ bgpd_rtr_conn_setup(struct rtr_config *r)
 	}
 
 	if (pfkey_establish(&ce->auth_state, &r->auth,
-	    &r->local_addr, &r->remote_addr) == -1)
+	    &r->local_addr, &r->remote_addr) == -1) {
 		log_warnx("rtr %s: pfkey setup failed", r->descr);
+		free(ce);
+		return;
+	}
 
 	ce->id = r->id;
 	ce->fd = socket(aid2af(r->remote_addr.aid),
@@ -1409,8 +1412,10 @@ bgpd_rtr_conn_setup(struct rtr_config *r)
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