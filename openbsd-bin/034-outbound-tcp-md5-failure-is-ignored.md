# Outbound TCP MD5 Failure Is Ignored

## Classification

security_control_failure, high severity, confidence: certain

## Affected Locations

`usr.sbin/bgpd/session.c:735`

## Summary

`session_connect()` attempts to enforce TCP MD5SIG for outbound BGP sessions, but the pre-patch code only logs `tcp_md5_set()` failure and continues to socket setup and `connect()`. For peers configured with TCP MD5SIG authentication, this fails open and can initiate an outbound BGP session without the required TCP MD5 protection.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

## Preconditions

- Peer has TCP MD5SIG authentication configured.
- `tcp_md5_set(peer->fd, &peer->auth_conf, &peer->conf.remote_addr)` returns `-1`.

## Proof

- `session_connect()` creates a nonblocking TCP socket for the configured peer.
- It rejects only the `sysdep.no_pfkey` case before calling `tcp_md5_set()`.
- When `tcp_md5_set()` returns `-1`, the vulnerable code logs `setting md5sig` but does not abort.
- Execution continues into `session_setup_socket()`, then `connect()`.
- A successful immediate connection reaches `bgp_fsm(peer, EVNT_CON_OPEN, NULL)`.
- An `EINPROGRESS` connection can later reach `EVNT_CON_OPEN` through the poll path.
- `tcp_md5_set()` can return `-1` for `AUTH_MD5SIG` when MD5SIG is unavailable or `setsockopt(TCP_MD5SIG)` fails, so the configured protection was not applied.

## Why This Is A Real Bug

TCP MD5SIG is an explicit authentication control for the peer. Once configured, outbound session establishment must depend on successfully applying that control. Continuing after `tcp_md5_set()` failure allows bgpd to initiate an unsigned outbound BGP TCP session, so an endpoint accepting unsigned TCP can complete a session despite local MD5 authentication being required.

## Fix Requirement

Abort `session_connect()` when `tcp_md5_set()` fails for an outbound MD5-authenticated peer. The failure path must signal connection-open failure and return without proceeding to bind, socket setup, or connect.

## Patch Rationale

The patch converts the logged-only `tcp_md5_set()` failure into a hard failure. It preserves the existing warning, raises `EVNT_CON_OPENFAIL`, and returns `-1`, matching nearby connection failure handling and preventing fail-open outbound sessions.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/bgpd/session.c b/usr.sbin/bgpd/session.c
index 7d6d234..22cb6bd 100644
--- a/usr.sbin/bgpd/session.c
+++ b/usr.sbin/bgpd/session.c
@@ -797,8 +797,11 @@ session_connect(struct peer *peer)
 	}
 
 	if (tcp_md5_set(peer->fd, &peer->auth_conf,
-	    &peer->conf.remote_addr) == -1)
+	    &peer->conf.remote_addr) == -1) {
 		log_peer_warn(&peer->conf, "setting md5sig");
+		bgp_fsm(peer, EVNT_CON_OPENFAIL, NULL);
+		return (-1);
+	}
 
 	/* if local-address is set we need to bind() */
 	bind_addr = session_localaddr(peer);
```