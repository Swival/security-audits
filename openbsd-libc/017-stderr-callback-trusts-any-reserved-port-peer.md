# stderr callback trusts any reserved-port peer

## Classification

Injection, medium severity.

## Affected Locations

`net/rcmd.c:240`

## Summary

`rcmd_af()` opens a reserved local listener for the stderr callback channel, sends that port to the remote `rcmd` server, and accepts the first inbound connection. The accepted socket is only checked for a reserved source port. It is not checked against the address of the already-connected primary peer, so any reachable host capable of binding a reserved source port can race the real server and impersonate the stderr/control channel.

## Provenance

Verified by reproduction from the supplied source and patch context.

Scanner provenance: [Swival Security Scanner](https://swival.dev)

Confidence: certain.

## Preconditions

- Attacker can reach the local stderr callback listener.
- Attacker can bind a reserved source port in the accepted range `[IPPORT_RESERVED / 2, IPPORT_RESERVED)`.
- Attacker connects before the legitimate remote `rcmd` server callback.

## Proof

In `rcmd_af()`, the primary connection is established with:

```c
connect(s, r->ai_addr, r->ai_addrlen)
```

When `fd2p` is requested, a second reserved listener is opened and advertised to the server:

```c
int s2 = rresvport_af(&lport, af), s3;
listen(s2, 1);
snprintf(num, sizeof(num), "%d", lport);
write(s, num, strlen(num)+1)
```

The callback path then accepts the first connection:

```c
s3 = accept(s2, (struct sockaddr *)&from, &len);
```

The only post-accept authentication checks are:

- reject source port `20` for FTP bounce mitigation;
- require source port to be reserved and at least `IPPORT_RESERVED / 2`.

No comparison is made between `from` and `r->ai_addr`. As a result, a malicious reserved-port-capable host can connect first from port `512` through `1023`, excluding `20`, and cause:

```c
*fd2p = s3;
```

The caller then receives an attacker-controlled file descriptor as the trusted stderr/control channel.

## Why This Is A Real Bug

The primary `rcmd` connection is made to a specific resolved peer address, but the auxiliary stderr channel accepts any peer that satisfies only the reserved-port convention. Reserved source ports are not unique to the authenticated remote host. A different reachable host with reserved-port bind capability can therefore win the race and inject data into the trusted stderr stream or receive control-channel bytes intended for the real remote command.

## Fix Requirement

The accepted stderr callback peer must match the authenticated primary connection peer address, in addition to satisfying the existing reserved-port validation.

## Patch Rationale

The patch stores the connected primary peer address before `freeaddrinfo(res)`:

```c
struct sockaddr_storage from, peer;
memcpy(&peer, r->ai_addr, r->ai_addrlen);
```

It then extends the callback validation to reject peers whose address family or address does not match the primary connection:

- `AF_INET`: compare `sin_addr.s_addr`;
- `AF_INET6`: compare `sin6_addr` with `IN6_ARE_ADDR_EQUAL`;
- `AF_INET6`: also compare `sin6_scope_id`.

The existing reserved-port range check remains in place. This binds the stderr callback to the same remote host as the established primary `rcmd` connection and prevents unrelated reserved-port-capable hosts from impersonating the channel.

## Residual Risk

None

## Patch

```diff
diff --git a/net/rcmd.c b/net/rcmd.c
index bf68603..c75aab4 100644
--- a/net/rcmd.c
+++ b/net/rcmd.c
@@ -64,7 +64,7 @@ rcmd_af(char **ahost, int porta, const char *locuser, const char *remuser,
 	char pbuf[NI_MAXSERV];
 	struct addrinfo hints, *res, *r;
 	int error;
-	struct sockaddr_storage from;
+	struct sockaddr_storage from, peer;
 	sigset_t oldmask, mask;
 	pid_t pid;
 	int s, lport;
@@ -179,6 +179,7 @@ rcmd_af(char **ahost, int porta, const char *locuser, const char *remuser,
 	}
 	/* given "af" can be PF_UNSPEC, we need the real af for "s" */
 	af = r->ai_family;
+	memcpy(&peer, r->ai_addr, r->ai_addrlen);
 	freeaddrinfo(res);
 	if (fd2p == 0) {
 		write(s, "", 1);
@@ -252,8 +253,18 @@ again:
 		switch (from.ss_family) {
 		case AF_INET:
 		case AF_INET6:
-			if (getnameinfo((struct sockaddr *)&from, len,
+			if (from.ss_family != peer.ss_family ||
+			    getnameinfo((struct sockaddr *)&from, len,
 			    NULL, 0, num, sizeof(num), NI_NUMERICSERV) != 0 ||
+			    (from.ss_family == AF_INET &&
+			    ((struct sockaddr_in *)&from)->sin_addr.s_addr !=
+			    ((struct sockaddr_in *)&peer)->sin_addr.s_addr) ||
+			    (from.ss_family == AF_INET6 &&
+			    (!IN6_ARE_ADDR_EQUAL(
+			    &((struct sockaddr_in6 *)&from)->sin6_addr,
+			    &((struct sockaddr_in6 *)&peer)->sin6_addr) ||
+			    ((struct sockaddr_in6 *)&from)->sin6_scope_id !=
+			    ((struct sockaddr_in6 *)&peer)->sin6_scope_id)) ||
 			    (atoi(num) >= IPPORT_RESERVED ||
 			     atoi(num) < IPPORT_RESERVED / 2)) {
 				(void)fprintf(stderr,
```