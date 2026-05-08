# Empty Route Report Indexes Before Stack Route Array

## Classification

Out-of-bounds read. Severity: high. Confidence: certain.

## Affected Locations

`usr.sbin/mrouted/route.c:755`

## Summary

`accept_report()` accepts an empty DVMRP route report from a recognized neighbor. When `datalen == 0`, no route entries are parsed, leaving `nrt == 0`. The function then evaluates `rt[nrt-1].origin`, which becomes `rt[-1].origin`, reading stack memory before the local `rt[4096]` array.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- The packet source passes `find_vif()`.
- The packet source passes `update_neighbor()`.
- The attacker is a neighboring DVMRP router or can send traffic accepted as one.
- The route report payload length is zero.

## Proof

The reproduced path is:

- `usr.sbin/mrouted/igmp.c:163` allows `igmpdatalen == 0`.
- `usr.sbin/mrouted/igmp.c:199` dispatches the packet as a DVMRP route report.
- `usr.sbin/mrouted/route.c:736` initializes `nrt = 0`.
- With `datalen == 0`, the parser loop at `usr.sbin/mrouted/route.c:758` is skipped.
- `qsort()` is called with zero elements at `usr.sbin/mrouted/route.c:797`.
- The default-route check at `usr.sbin/mrouted/route.c:802` evaluates `rt[nrt-1].origin`, which is `rt[-1].origin`.
- `rt` is a stack array declared as `struct newrt rt[4096]` at `usr.sbin/mrouted/route.c:740`.

A minimal ASan harness forcing `find_vif()` and `update_neighbor()` to succeed with `datalen = 0` reports a stack-buffer-overflow read at the default-route check.

## Why This Is A Real Bug

The parser explicitly permits the zero-length case because it only enters the route parsing loop while `datalen > 0`. No later guard verifies that at least one route was parsed before indexing the last element. Since `nrt` remains zero, `nrt - 1` is negative and indexes before the stack array. The input is reachable from a malicious adjacent DVMRP peer because accepted neighbors can trigger `accept_report()` with an empty report.

## Fix Requirement

Guard the last-entry default-route check with `nrt > 0`, or reject empty route reports before reaching that check.

## Patch Rationale

The patch adds the missing cardinality guard:

```c
if (nrt > 0 && rt[nrt-1].origin == 0)
	rt[nrt-1].mask = 0;
```

This preserves existing behavior for valid non-empty reports while preventing access to `rt[-1]` when the report contains zero parsed routes.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/mrouted/route.c b/usr.sbin/mrouted/route.c
index 9271eb2..cb4fe38 100644
--- a/usr.sbin/mrouted/route.c
+++ b/usr.sbin/mrouted/route.c
@@ -799,7 +799,7 @@ accept_report(u_int32_t src, u_int32_t dst, char *p, int datalen,
     /*
      * If the last entry is default, change mask from 0xff000000 to 0
      */
-    if (rt[nrt-1].origin == 0)
+    if (nrt > 0 && rt[nrt-1].origin == 0)
 	rt[nrt-1].mask = 0;
 
     logit(LOG_DEBUG, 0, "Updating %d routes from %s to %s", nrt,
```