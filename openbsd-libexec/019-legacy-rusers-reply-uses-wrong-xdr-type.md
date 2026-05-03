# legacy rusers reply uses wrong XDR type

## Classification

Out-of-bounds read. Severity: medium. Confidence: certain.

## Affected Locations

`rpc.rusersd/rusers_proc.c:364`

`rpc.rusersd/rusers_proc.c:392`

## Summary

Legacy `RUSERSVERS_ORIG` `NAMES` and `ALLNAMES` replies select the wrong XDR encoder. The service handlers return `struct utmparr`, but `rusers_service()` sends those results with `xdr_utmpidlearr`, causing the RPC encoder to interpret legacy `struct ru_utmp` entries as larger `struct utmpidle` entries and serialize memory past the intended objects.

## Provenance

Reported and reproduced from Swival Security Scanner findings: https://swival.dev

## Preconditions

- `rpc.rusersd` exposes the legacy `RUSERSVERS_ORIG` service.
- At least one matching utmp entry exists for a triggerable out-of-bounds read.
- Two or more returned users make adjacent initialized data or pointer bits reliably observable in the RPC response.

## Proof

For `RUSERSPROC_NAMES` with `rq_vers == RUSERSVERS_ORIG`, `rusers_service()` dispatches to `rusersproc_names_1_svc`, which returns the result of `do_names_1()`.

For `RUSERSPROC_ALLNAMES` with `rq_vers == RUSERSVERS_ORIG`, `rusers_service()` dispatches to `rusersproc_allnames_1_svc`, which also returns the result of `do_names_1()`.

`do_names_1()` constructs a static `struct utmparr`:

- `ut.uta_arr = ru_utmpp`
- each `ru_utmpp[nusers] = &ru_utmp[nusers]`
- each returned entry is a `struct ru_utmp`

Before the patch, both legacy dispatch paths set:

```c
xdr_result = (xdrproc_t)xdr_utmpidlearr;
```

`svc_sendreply()` therefore encodes the returned `struct utmparr` buffer as a `struct utmpidlearr`. `xdr_utmpidlearr` expects each element to be a `struct utmpidle`, which contains a `struct ru_utmp` plus `ui_idle`. That makes the encoder read the `ui_idle` word immediately after each actual `struct ru_utmp`.

With multiple returned entries, the extra word is read from adjacent daemon memory, commonly data associated with the next returned entry. With `MAXUSERS` returned entries, the final oversized read crosses the complete `ru_utmp` array.

## Why This Is A Real Bug

The selected XDR routine does not match the concrete object returned by the service function. The legacy version-1 handlers return `struct utmparr`, not `struct utmpidlearr`.

Because XDR encoding walks the object according to the selected routine, this is not a type-only correctness issue. It changes the memory layout used during serialization and causes reads beyond each `struct ru_utmp` object. The over-read bytes are sent to an unauthenticated network RPC client in the reply.

## Fix Requirement

Use `xdr_utmparr` for `RUSERSVERS_ORIG` replies from:

- `RUSERSPROC_NAMES`
- `RUSERSPROC_ALLNAMES`

Keep `xdr_utmpidlearr` only for `RUSERSVERS_IDLE`, whose handlers return `struct utmpidlearr`.

## Patch Rationale

The patch changes only the XDR result routine for the two legacy version-1 dispatch cases. This aligns the serializer with the return type of `rusersproc_names_1_svc()` and `rusersproc_allnames_1_svc()`.

The version-2 idle paths remain unchanged because they return `struct utmpidlearr` and require `xdr_utmpidlearr`. The version-3 paths remain unchanged because they use `xdr_utmp_array`.

## Residual Risk

None

## Patch

```diff
diff --git a/rpc.rusersd/rusers_proc.c b/rpc.rusersd/rusers_proc.c
index 1f3ea75..f6449d4 100644
--- a/rpc.rusersd/rusers_proc.c
+++ b/rpc.rusersd/rusers_proc.c
@@ -362,7 +362,7 @@ rusers_service(struct svc_req *rqstp, SVCXPRT *transp)
 			break;
 
 		case RUSERSVERS_ORIG:
-			xdr_result = (xdrproc_t)xdr_utmpidlearr;
+			xdr_result = (xdrproc_t)xdr_utmparr;
 			local = (char *(*)(void *, struct svc_req *))
 			    rusersproc_names_1_svc;
 			break;
@@ -390,7 +390,7 @@ rusers_service(struct svc_req *rqstp, SVCXPRT *transp)
 			break;
 
 		case RUSERSVERS_ORIG:
-			xdr_result = (xdrproc_t)xdr_utmpidlearr;
+			xdr_result = (xdrproc_t)xdr_utmparr;
 			local = (char *(*)(void *, struct svc_req *))
 			    rusersproc_allnames_1_svc;
 			break;
```