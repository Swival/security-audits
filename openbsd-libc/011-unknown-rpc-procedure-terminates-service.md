# Unknown RPC Procedure Terminates Service

## Classification

Denial of service, high severity.

## Affected Locations

`rpc/svc_simple.c:123`

## Summary

The simplified RPC dispatcher registered by `registerrpc()` exits the server process when it receives a non-`NULLPROC` request for an unregistered procedure. A remote RPC client can trigger this path by sending a request for a registered program/version with an absent nonzero procedure number, causing deterministic service termination.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The service uses `registerrpc()` simplified UDP dispatch.
- The attacker can send RPC requests to the registered program/version.
- The attacker chooses a nonzero procedure number not present in the `proglst` registration list.

## Proof

`registerrpc()` creates a UDP transport and registers `universal()` as the dispatcher for the supplied program/version.

In `universal()`:

- `NULLPROC` is handled specially and returns an empty reply.
- For nonzero procedures, attacker-controlled `rqstp->rq_proc` is copied into `proc`.
- The dispatcher searches `proglst` for a matching program and procedure.
- If no matching entry exists, control falls through to `exit(1)`.

Relevant vulnerable control flow:

```c
for (pl = proglst; pl != NULL; pl = pl->p_nxt)
	if (pl->p_prognum == prog && pl->p_procnum == proc) {
		...
		return;
	}
exit(1);
```

Thus, a single remote request using a registered program/version and an unregistered nonzero procedure terminates the server instead of returning an RPC error.

## Why This Is A Real Bug

The exit is reached from normal remote request processing on attacker-controlled input. The failure condition does not require memory corruption, races, authentication bypass, or local access. The code deterministically terminates the process when the procedure lookup misses, denying all RPC service handled by that process.

RPC dispatchers are expected to report unknown procedures to the client, not abort the server. The appropriate behavior is to return a “no such procedure” RPC error.

## Fix Requirement

Replace the final process termination with an RPC error response for an unknown procedure, such as `svcerr_noproc(transp)`.

## Patch Rationale

The patch preserves existing behavior for:

- `NULLPROC` handling.
- Registered procedure lookup and dispatch.
- Decode error reporting.
- Successful replies.
- Existing reply-send failure handling.

Only the unmatched-procedure path changes. Instead of terminating the process, the dispatcher now sends the standard RPC “no such procedure” error to the client and returns normally.

## Residual Risk

None

## Patch

```diff
diff --git a/rpc/svc_simple.c b/rpc/svc_simple.c
index 9675332..0600b24 100644
--- a/rpc/svc_simple.c
+++ b/rpc/svc_simple.c
@@ -121,6 +121,6 @@ universal(struct svc_req *rqstp, SVCXPRT *transp)
 			(void)svc_freeargs(transp, pl->p_inproc, xdrbuf);
 			return;
 		}
-	exit(1);
+	svcerr_noproc(transp);
 }
```