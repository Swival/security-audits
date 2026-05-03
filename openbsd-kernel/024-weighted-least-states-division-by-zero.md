# Weighted Least-States Division By Zero

## Classification

Denial of service, high severity, certain confidence.

## Affected Locations

`net/pf_lb.c:561`

## Summary

`pf_map_addr()` can divide by zero while selecting an address from a weighted `PF_POOL_LEASTSTATES` table or dynamic interface pool. If the current pool member has `rpool->weight == 0`, weighted load calculation executes in kernel context and traps, allowing matching remote traffic to deny service.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- A PF rule uses `least-states` for NAT, RDR, or route-to address selection.
- The selected pool is a table or dynamic interface pool.
- The table has at least one weighted/cost entry, making `pfrkt_refcntcost > 0`.
- A selected/current table member can leave `rpool->weight` as `0`, specifically through the reproduced `PFRKE_ROUTE` path.

## Proof

The reproduced path is source-supported:

- `pfr_pool_get()` sets `rpool->weight` for `PFRKE_COST` entries and defaults plain entries to `1`, but `PFRKE_ROUTE` only sets `rpool->kif` and leaves `rpool->weight` unchanged at `net/pf_table.c:2717`.
- `pf_pool_copyin()` copies the pool from the rule and only clears `kif` and `addr.p.tbl`, preserving an initial runtime `weight` of `0` at `net/pf_ioctl.c:3984`.
- If the least-states table contains at least one `PFRKE_COST`, `pfrkt_refcntcost > 0`, so `pf_map_addr()` enters weighted load calculation at `net/pf_lb.c:568`.
- When the selected/current table member is `PFRKE_ROUTE` while `rpool->weight == 0`, `pf_map_addr()` executes `(UINT16_MAX * rpool->states) / rpool->weight` at `net/pf_lb.c:572`.
- The same unchecked divisor is used for candidate load calculation while iterating alternatives at `net/pf_lb.c:596`.

Remote traffic matching a vulnerable rule can reach this path through NAT/RDR translation at `net/pf_lb.c:722` or route-to processing at `net/pf.c:4369`.

## Why This Is A Real Bug

The divisor is data-dependent and not guaranteed nonzero. The code assumes weighted table selection implies a valid positive `rpool->weight`, but the reproduced `PFRKE_ROUTE` path leaves the field unchanged. Since `pf_map_addr()` performs integer division in kernel context, a zero weight deterministically causes a division-by-zero trap rather than a recoverable rule failure.

## Fix Requirement

Reject zero-weight pool members or treat them as ineligible before any weighted least-states division.

## Patch Rationale

The patch adds explicit `rpool->weight == 0` checks immediately before both weighted load divisions in `PF_POOL_LEASTSTATES`.

This is the minimal safe fix because it:

- Preserves existing weighted least-states behavior for positive weights.
- Prevents both initial selected-address and iterated-candidate division by zero.
- Converts malformed/ineligible zero-weight selection into a clean address-mapping failure with `return (1)`.
- Avoids relying on all `pfr_pool_get()` entry types to initialize `rpool->weight`.

## Residual Risk

None

## Patch

```diff
diff --git a/net/pf_lb.c b/net/pf_lb.c
index 329427f..0b8e466 100644
--- a/net/pf_lb.c
+++ b/net/pf_lb.c
@@ -568,9 +568,11 @@ pf_map_addr(sa_family_t af, struct pf_rule *r, struct pf_addr *saddr,
 		if ((rpool->addr.type == PF_ADDR_TABLE &&
 		    rpool->addr.p.tbl->pfrkt_refcntcost > 0) ||
 		    (rpool->addr.type == PF_ADDR_DYNIFTL &&
-		    rpool->addr.p.dyn->pfid_kt->pfrkt_refcntcost > 0))
+		    rpool->addr.p.dyn->pfid_kt->pfrkt_refcntcost > 0)) {
+			if (rpool->weight == 0)
+				return (1);
 			load = ((UINT16_MAX * rpool->states) / rpool->weight);
-		else
+		} else
 			load = states;
 
 		pf_addrcpy(&faddr, &rpool->counter, af);
@@ -596,10 +598,12 @@ pf_map_addr(sa_family_t af, struct pf_rule *r, struct pf_addr *saddr,
 			if ((rpool->addr.type == PF_ADDR_TABLE &&
 			    rpool->addr.p.tbl->pfrkt_refcntcost > 0) ||
 			    (rpool->addr.type == PF_ADDR_DYNIFTL &&
-			    rpool->addr.p.dyn->pfid_kt->pfrkt_refcntcost > 0))
+			    rpool->addr.p.dyn->pfid_kt->pfrkt_refcntcost > 0)) {
+				if (rpool->weight == 0)
+					return (1);
 				cload = ((UINT16_MAX * rpool->states)
 					/ rpool->weight);
-			else
+			} else
 				cload = rpool->states;
 
 			/* find lc minimum */
```