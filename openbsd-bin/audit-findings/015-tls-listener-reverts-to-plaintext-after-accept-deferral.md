# TLS listener reverts to plaintext after accept deferral

## Classification

Authentication bypass, high severity. Confidence: certain.

## Affected Locations

`usr.sbin/syslogd/syslogd.c:936`

Primary vulnerable call site: `usr.sbin/syslogd/syslogd.c:1146`

## Summary

A TLS syslog listener can be re-armed with the TCP accept callback after file-descriptor exhaustion defers `accept4()`. When the timeout fires, the TLS listener accepts later clients as plaintext TCP, bypassing TLS handshake and client-certificate authentication.

## Provenance

Identified by Swival Security Scanner: https://swival.dev

## Preconditions

- `syslogd` TLS listener is enabled.
- Accept deferral is reachable, e.g. `EMFILE` or `ENFILE`.
- Client certificate authentication is configured with `-K ServerCAfile`.

## Proof

`tls_acceptcb()` calls `acceptcb(..., 1)`, but the vulnerable code passed `tcp_acceptcb` unconditionally into `reserve_accept4()`.

On `EMFILE` or `ENFILE`, `reserve_accept4()` deletes the listener event and re-adds it as a timeout using the supplied callback. Because the supplied callback was `tcp_acceptcb`, the timeout path later invoked `acceptcb(..., 0)` on the TLS listener.

That changes later accepted connections from the TLS path to the plaintext path:

- Plaintext path: `bufferevent_new(... tcp_readcb ...)` at `usr.sbin/syslogd/syslogd.c:1179`
- TLS path skipped: `tls_accept_socket()` at `usr.sbin/syslogd/syslogd.c:1190`
- Log ingestion then reaches `printline()` from `tcp_readcb()` at `usr.sbin/syslogd/syslogd.c:1355`

The trigger is practical because remote clients can hold many accepted TLS connections open until:

`getdtablecount() + FD_RESERVE >= getdtablesize()`

forces the `EMFILE` deferral path at `usr.sbin/syslogd/syslogd.c:1101`.

## Why This Is A Real Bug

`-K ServerCAfile` configures the TLS server to verify client certificates via `tls_config_verify_client(server_config)` at `usr.sbin/syslogd/syslogd.c:693`. That makes the TLS handshake and client certificate check the intended authentication control for inbound TLS syslog.

After the callback mismatch, the same TLS listener accepts plaintext TCP frames. Those frames are parsed by `tcp_readcb()` and logged without `tls_accept_socket()`, without `tls_handshakecb()`, and without client certificate validation.

## Fix Requirement

The callback passed to `reserve_accept4()` must preserve the listener protocol across accept deferral. TLS listeners must be re-armed with `tls_acceptcb`; TCP listeners must be re-armed with `tcp_acceptcb`.

## Patch Rationale

The patch selects the reserve callback from `usetls`:

```c
usetls ? tls_acceptcb : tcp_acceptcb
```

This keeps timeout re-arming protocol-faithful. When a TLS listener hits accept deferral, the timeout fires `tls_acceptcb`, which calls `acceptcb(..., 1)`, preserving TLS setup, handshake handling, and client-certificate authentication.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/syslogd/syslogd.c b/usr.sbin/syslogd/syslogd.c
index dfa741c..67bca2b 100644
--- a/usr.sbin/syslogd/syslogd.c
+++ b/usr.sbin/syslogd/syslogd.c
@@ -1143,7 +1143,8 @@ acceptcb(int lfd, short event, void *arg, int usetls)
 	int			 fd, error;
 
 	sslen = sizeof(ss);
-	if ((fd = reserve_accept4(lfd, event, ev, tcp_acceptcb,
+	if ((fd = reserve_accept4(lfd, event, ev,
+	    usetls ? tls_acceptcb : tcp_acceptcb,
 	    (struct sockaddr *)&ss, &sslen, SOCK_NONBLOCK)) == -1) {
 		if (errno != ENFILE && errno != EMFILE &&
 		    errno != EINTR && errno != EWOULDBLOCK &&
```