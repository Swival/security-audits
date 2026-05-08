# UDP version mismatch range drives four-billion probe loop

## Classification

Denial of service, medium severity.

## Affected Locations

`usr.bin/rpcinfo/rpcinfo.c:306`

## Summary

When `rpcinfo -u` is run without an explicit version, `udpping()` trusts the version range advertised in an `RPC_PROGVERSMISMATCH` response. A malicious UDP RPC service can return `low = 0` and `high = 4294967295`, causing `rpcinfo` to iterate over the entire advertised range and issue roughly four billion UDP RPC probes.

## Provenance

Verified by reproduction from a Swival Security Scanner finding: https://swival.dev

Confidence: certain.

## Preconditions

- The user runs `rpcinfo -u attacker-host program` without an explicit version.
- The attacker controls the contacted UDP RPC service.
- If `-n port` is not supplied, the attacker-controlled host must direct the client to the malicious UDP service, for example via portmapper.
- If `-n port` is supplied, the malicious UDP service is contacted directly.

## Proof

In the no-version UDP path, `udpping()` first probes version `0`. If the peer replies with `RPC_PROGVERSMISMATCH`, the code copies the peer-controlled range directly:

- `minvers = rpcerr.re_vers.low`
- `maxvers = rpcerr.re_vers.high`

The inclusive loop then runs from `minvers` through `maxvers`:

```c
for (vers = minvers; vers <= maxvers; vers++) {
        ...
        client = clntudp_create(&addr, prognum, vers, to, &sock);
        ...
        rpc_stat = clnt_call(client, NULLPROC, xdr_void,
            (char *)NULL, xdr_void, (char *)NULL, to);
        ...
}
```

With `low = 0` and `high = 4294967295`, an LP64 build performs `2^32` probes. On an ILP32 build, `u_long` wraparound can make the loop non-terminating.

## Why This Is A Real Bug

The loop bound is fully attacker-controlled through the RPC mismatch response. No committed-code check caps the advertised range before the code creates a UDP client and performs an RPC call for every version. The attack deterministically occupies the victim `rpcinfo` process until completion or manual termination, and the requested command form is a normal supported use of `rpcinfo`.

## Fix Requirement

Reject malformed or excessive peer-advertised version ranges before probing individual versions. The program should require the user to specify an explicit version when the advertised range is too large.

## Patch Rationale

The patch adds `MAX_VERS_RANGE` and validates the copied range before entering the probe loop:

```c
#define MAX_VERS_RANGE 256
...
if (maxvers < minvers || maxvers - minvers >= MAX_VERS_RANGE)
        errx(1, "version range too large; specify a version");
```

This prevents both inverted ranges and attacker-selected massive ranges from driving an unbounded or multi-billion-iteration UDP probe loop. Legitimate small version ranges are still probed automatically, while large ranges require explicit user intent.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/rpcinfo/rpcinfo.c b/usr.bin/rpcinfo/rpcinfo.c
index 124b894..bbb2b92 100644
--- a/usr.bin/rpcinfo/rpcinfo.c
+++ b/usr.bin/rpcinfo/rpcinfo.c
@@ -56,6 +56,7 @@
 
 #define	MIN_VERS	((u_long) 0)
 #define	MAX_VERS	((u_long) 4294967295UL)
+#define	MAX_VERS_RANGE	256
 
 void	udpping(u_short portflag, int argc, char **argv);
 void	tcpping(u_short portflag, int argc, char **argv);
@@ -294,6 +295,8 @@ udpping(u_short portnum, int argc, char **argv)
 			exit(1);
 		}
 		clnt_destroy(client);
+		if (maxvers < minvers || maxvers - minvers >= MAX_VERS_RANGE)
+			errx(1, "version range too large; specify a version");
 		for (vers = minvers; vers <= maxvers; vers++) {
 			addr.sin_port = htons(portnum);
 			to.tv_sec = 5;
```