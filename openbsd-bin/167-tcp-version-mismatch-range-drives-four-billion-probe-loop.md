# TCP version mismatch range drives four-billion probe loop

## Classification

Denial of service, medium severity.

## Affected Locations

`usr.bin/rpcinfo/rpcinfo.c:437`

## Summary

`rpcinfo -t` without an explicit version trusts the version range returned in an attacker-controlled `RPC_PROGVERSMISMATCH` reply. A malicious TCP RPC server can advertise `low = 0` and `high = 4294967295`, causing `rpcinfo` to iterate across the full 32-bit version space and issue billions of sequential TCP/RPC probes.

The patch caps automatic TCP version probing to 100 versions and requires the user to specify a version for larger ranges.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- User runs `rpcinfo -t` without an explicit version.
- Target host is attacker-controlled or routes to a malicious RPC TCP server.
- The malicious server replies to the initial NULLPROC probe with `RPC_PROGVERSMISMATCH`.
- The mismatch reply advertises an excessive version range, such as `low = 0`, `high = 4294967295`.

## Proof

In `tcpping()`, the no-version path probes version `MIN_VERS` first:

```c
client = clnttcp_create(&addr, prognum, MIN_VERS, &sock, 0, 0);
rpc_stat = clnt_call(client, NULLPROC, xdr_void, (char *)NULL,
    xdr_void, (char *)NULL, to);
```

If the attacker returns `RPC_PROGVERSMISMATCH`, the code copies the advertised bounds directly:

```c
clnt_geterr(client, &rpcerr);
minvers = rpcerr.re_vers.low;
maxvers = rpcerr.re_vers.high;
```

Those values then drive the TCP probing loop:

```c
for (vers = minvers; vers <= maxvers; vers++) {
	client = clnttcp_create(&addr, prognum, vers, &sock, 0, 0);
	rpc_stat = clnt_call(client, 0, xdr_void, (char *)NULL,
	    xdr_void, (char *)NULL, to);
}
```

Because `MAX_VERS` is `4294967295UL`, a malicious mismatch range of `0..4294967295` produces `4,294,967,296` sequential probe attempts. Each iteration opens a TCP client and sends a NULLPROC call to the attacker-controlled endpoint.

## Why This Is A Real Bug

The loop bound is remotely influenced by the RPC server and was not validated before use. The result is attacker-triggered, long-running resource consumption in the victim `rpcinfo` process, plus attacker-directed TCP/RPC activity.

This is reachable only in the no-version TCP discovery path. Supplying an explicit version avoids the automatic range loop.

## Fix Requirement

Before iterating over an advertised TCP version range, the client must reject ranges large enough to cause excessive probing, or require the user to provide an explicit version.

The fix must also avoid unsigned wraparound in the `vers <= maxvers; vers++` loop when `maxvers` is the maximum representable version.

## Patch Rationale

The patch adds:

```c
#define	MAX_VERS_PROBES	100
```

Before the TCP version loop, it rejects ranges of 100 or more increments:

```c
if (maxvers >= minvers && maxvers - minvers >= MAX_VERS_PROBES)
	errx(1, "too many versions; specify a version");
```

This prevents attacker-supplied ranges such as `0..4294967295` from driving billions of probes.

The patch also adds an explicit loop exit after processing `maxvers`:

```c
if (vers == maxvers)
	break;
```

This prevents unsigned wraparound when `vers` reaches `maxvers`, including the `MAX_VERS` case.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/rpcinfo/rpcinfo.c b/usr.bin/rpcinfo/rpcinfo.c
index 124b894..000ce39 100644
--- a/usr.bin/rpcinfo/rpcinfo.c
+++ b/usr.bin/rpcinfo/rpcinfo.c
@@ -56,6 +56,7 @@
 
 #define	MIN_VERS	((u_long) 0)
 #define	MAX_VERS	((u_long) 4294967295UL)
+#define	MAX_VERS_PROBES	100
 
 void	udpping(u_short portflag, int argc, char **argv);
 void	tcpping(u_short portflag, int argc, char **argv);
@@ -420,6 +421,8 @@ tcpping(u_short portnum, int argc, char **argv)
 		clnt_destroy(client);
 		(void) close(sock);
 		sock = RPC_ANYSOCK; /* Re-initialize it for later */
+		if (maxvers >= minvers && maxvers - minvers >= MAX_VERS_PROBES)
+			errx(1, "too many versions; specify a version");
 		for (vers = minvers; vers <= maxvers; vers++) {
 			addr.sin_port = htons(portnum);
 			if ((client = clnttcp_create(&addr, prognum, vers,
@@ -438,6 +441,8 @@ tcpping(u_short portnum, int argc, char **argv)
 			clnt_destroy(client);
 			(void) close(sock);
 			sock = RPC_ANYSOCK;
+			if (vers == maxvers)
+				break;
 		}
 	} else {
 		getul(argv[2], &vers);		/* XXX */
```