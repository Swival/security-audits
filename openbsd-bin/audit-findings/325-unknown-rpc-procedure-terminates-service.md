# Unknown RPC Procedure Terminates Service

## Classification

Denial of service, medium severity.

## Affected Locations

`usr.sbin/ypserv/yppush/yppush_svc.c:92`

## Summary

The `yppush` RPC callback dispatcher terminates its process when it receives an unsupported RPC procedure number. A remote RPC client that can reach the transient `yppush` service can send an unknown `rq_proc` value and force the callback service process to exit.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

The attacker can send RPC requests to the `yppush` service.

## Proof

`yppush_xfrrespprog_1()` dispatches on `rqstp->rq_proc`.

Only these procedures are handled:

- `YPPUSHPROC_NULL`
- `YPPUSHPROC_XFRRESP`

For all other procedure numbers, the default branch executes:

```c
svcerr_noproc(transp);
_rpcsvcdirty = 0;
exit(1);
return;
```

This occurs before argument decoding or caller validation. Therefore, an attacker-controlled RPC request with an unsupported procedure number deterministically reaches `exit(1)` and terminates the service process.

The reproduced behavior also showed that the parent observes the child exit via `wait4()` and unregisters the callback, confirming service disruption for the active push operation.

## Why This Is A Real Bug

Unknown RPC procedures are normal protocol errors and should be reported with `svcerr_noproc()` without killing the service. Here, the error path exits the process. The trigger is fully attacker-controlled through `rqstp->rq_proc`, and the impact is deterministic termination of the active `yppush` RPC callback process.

The scope is limited to the transient callback service for the current push operation, but the denial-of-service behavior is concrete.

## Fix Requirement

After sending `svcerr_noproc(transp)`, the dispatcher must return to the RPC service loop instead of exiting the process.

## Patch Rationale

The patch removes `exit(1)` from the unknown-procedure default branch while preserving the protocol error response and `_rpcsvcdirty` cleanup.

This makes unsupported procedure numbers non-fatal:

```c
default:
	svcerr_noproc(transp);
	_rpcsvcdirty = 0;
	return;
```

Handled procedures retain their existing behavior.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/ypserv/yppush/yppush_svc.c b/usr.sbin/ypserv/yppush/yppush_svc.c
index b0ed5cb..1b687de 100644
--- a/usr.sbin/ypserv/yppush/yppush_svc.c
+++ b/usr.sbin/ypserv/yppush/yppush_svc.c
@@ -89,7 +89,6 @@ yppush_xfrrespprog_1(struct svc_req *rqstp, SVCXPRT *transp)
 	default:
 		svcerr_noproc(transp);
 		_rpcsvcdirty = 0;
-		exit(1);
 		return;
 	}
 	(void) memset(&argument, 0, sizeof(argument));
```