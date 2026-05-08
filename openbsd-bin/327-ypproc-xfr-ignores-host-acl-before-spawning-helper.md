# YPPROC_XFR ignores host ACL before spawning helper

## Classification

Authorization bypass, medium severity. Confidence: certain.

## Affected Locations

`usr.sbin/ypserv/ypserv/ypserv_proc.c:249`

## Summary

`ypproc_xfr_2_svc` computes the caller host ACL result with `acl_check_host`, but does not enforce it before spawning `/usr/sbin/ypxfr`. A host denied by `ypserv` ACLs can still invoke `YPPROC_XFR` from a reserved source port and cause `ypserv` to execute the privileged transfer helper with RPC-controlled arguments.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- Attacker can send RPC traffic to `ypserv`.
- Attacker can use a reserved source port below `IPPORT_RESERVED`.
- Attacker supplies slash-free `map_parms.domain` and `map_parms.map` values.
- Attacker source host is denied by the configured `ypserv` host ACL.

## Proof

The RPC dispatcher decodes attacker-controlled `ypreq_xfr` data and calls `ypproc_xfr_2_svc`.

Inside `ypproc_xfr_2_svc`, the server evaluates the host ACL:

```c
int ok = acl_check_host(&caller->sin_addr);
```

The value is logged through `TORF(ok)`, but the rejection condition only checks path separators and source port privilege:

```c
if (strchr(argp->map_parms.domain, '/') ||
    strchr(argp->map_parms.map, '/') ||
    ntohs(caller->sin_port) >= IPPORT_RESERVED) {
        svcerr_auth(rqstp->rq_xprt, AUTH_FAILED);
        return(NULL);
}
```

Because `!ok` is absent, an ACL-denied caller using a reserved source port and slash-free domain/map values reaches:

```c
pid = vfork();
```

The child then executes:

```c
execl(ypxfr_proc, "ypxfr", "-d", argp->map_parms.domain,
    "-C", tid, prog, ipadd, port, argp->map_parms.map, (char *)NULL);
```

The denied remote host therefore bypasses the documented host ACL and triggers `/usr/sbin/ypxfr` with attacker-controlled domain, transaction id, program, port, and map arguments.

## Why This Is A Real Bug

Other `ypserv` procedures enforce `acl_check_host` by rejecting `!ok` before serving requests or spawning helpers. The documented ACL behavior is that denied hosts are blocked from server access. `YPPROC_XFR` is inconsistent: it calculates the ACL result but only logs it, allowing denied clients to reach privileged helper execution. This is a direct authorization bypass, not a logging-only issue.

## Fix Requirement

Reject `YPPROC_XFR` requests when `acl_check_host` returns false, before `vfork()` and before any `execl()` of `YPXFR_PROC`.

## Patch Rationale

The patch adds `!ok` to the existing authentication failure condition in `ypproc_xfr_2_svc`. This preserves existing validation for slash-containing domain/map values and non-reserved source ports, while enforcing the same host ACL decision already computed for logging and used by adjacent service procedures.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/ypserv/ypserv/ypserv_proc.c b/usr.sbin/ypserv/ypserv/ypserv_proc.c
index ed72977..2427466 100644
--- a/usr.sbin/ypserv/ypserv/ypserv_proc.c
+++ b/usr.sbin/ypserv/ypserv/ypserv_proc.c
@@ -247,7 +247,7 @@ ypproc_xfr_2_svc(ypreq_xfr *argp, struct svc_req *rqstp)
 	YPLOG("       ipadd=%s, port=%d, map=%s", inet_ntoa(caller->sin_addr),
 	    argp->port, argp->map_parms.map);
 
-	if (strchr(argp->map_parms.domain, '/') ||
+	if (!ok || strchr(argp->map_parms.domain, '/') ||
 	    strchr(argp->map_parms.map, '/') ||
 	    ntohs(caller->sin_port) >= IPPORT_RESERVED) {
 		svcerr_auth(rqstp->rq_xprt, AUTH_FAILED);
```