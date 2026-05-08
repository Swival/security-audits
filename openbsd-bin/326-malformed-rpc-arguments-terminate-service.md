# Malformed RPC Arguments Terminate Service

## Classification

Denial of service, medium severity.

## Affected Locations

`usr.sbin/ypserv/yppush/yppush_svc.c:99`

## Summary

A reachable RPC client can send malformed XDR arguments to `YPPUSHPROC_XFRRESP` and cause the `yppush` RPC callback service process to terminate. The dispatcher treats argument decode failure as a fatal process error by calling `exit(1)` after `svc_getargs()` fails.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The `yppush` service is active.
- The transient UDP RPC callback service is reachable by the attacking RPC client.
- The attacker can send a `YPPUSHPROC_XFRRESP` RPC request with malformed or truncated XDR arguments.

## Proof

`usr.sbin/ypserv/yppush/yppush.c:162` creates a UDP RPC callback transport, and `usr.sbin/ypserv/yppush/yppush.c:174` registers `yppush_xfrrespprog_1` as the dispatcher for the transient callback program.

The forked child enters `my_svc_run()` at `usr.sbin/ypserv/yppush/yppush.c:189`, so remote RPC traffic to that registered UDP service reaches the dispatcher while `yppush` is active.

For `YPPUSHPROC_XFRRESP`, `usr.sbin/ypserv/yppush/yppush_svc.c:82` selects `xdr_yppushresp_xfr` as the argument decoder.

If a client sends malformed or truncated XDR arguments, `svc_getargs()` fails at `usr.sbin/ypserv/yppush/yppush_svc.c:96`. The failure path sends `svcerr_decode()`, clears `_rpcsvcdirty`, and then calls `exit(1)` at `usr.sbin/ypserv/yppush/yppush_svc.c:99`.

There is no caller authentication or source validation in this callback dispatcher, so a reachable remote RPC client can terminate the forked `yppush` RPC callback service before the legitimate transfer response arrives.

## Why This Is A Real Bug

Malformed RPC arguments are client-controlled input and should be handled as a per-request decode error. Terminating the whole service process on a bad request lets any reachable RPC client convert invalid XDR into a denial of service.

The existing code already reports the decode error with `svcerr_decode(transp)` and resets `_rpcsvcdirty`. Continuing to `exit(1)` is unnecessary for protocol correctness and makes the process availability dependent on well-formed attacker-controlled input.

## Fix Requirement

On `svc_getargs()` decode failure, the dispatcher must report the RPC decode error and return to the service loop instead of exiting the process.

## Patch Rationale

The patch removes the fatal `exit(1)` from the `svc_getargs()` failure path. The handler still calls `svcerr_decode(transp)` so the client receives the correct RPC error response, and it still clears `_rpcsvcdirty` before returning.

This preserves normal error handling while preventing malformed request arguments from terminating the callback service process.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/ypserv/yppush/yppush_svc.c b/usr.sbin/ypserv/yppush/yppush_svc.c
index b0ed5cb..a212d56 100644
--- a/usr.sbin/ypserv/yppush/yppush_svc.c
+++ b/usr.sbin/ypserv/yppush/yppush_svc.c
@@ -96,7 +96,6 @@ yppush_xfrrespprog_1(struct svc_req *rqstp, SVCXPRT *transp)
 	if (!svc_getargs(transp, xdr_argument, (caddr_t)&argument)) {
 		svcerr_decode(transp);
 		_rpcsvcdirty = 0;
-		exit(1);
 		return;
 	}
 	result = (*local)(&argument, rqstp);
```