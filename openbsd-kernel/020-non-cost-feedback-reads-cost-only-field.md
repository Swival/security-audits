# Non-Cost Feedback Reads Cost-Only Field

## Classification

Information disclosure, medium severity, confidence certain.

## Affected Locations

`net/pf_table.c:310`

## Summary

`pfr_fill_feedback()` returned feedback for table addresses by always reading `((struct pfr_kentry_cost *)ke)->weight`, even when the entry was not `PFRKE_COST`. For `PFRKE_PLAIN`, the object is allocated as `sizeof(struct pfr_kentry)`, so the cost-only `weight` field is outside the allocated plain-entry object. The value is copied back to userland in `pfra_weight`, disclosing kernel heap bytes.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

An attacker can modify a non-const active pf table and can issue pf table-address additions with `PFR_FLAG_FEEDBACK`.

## Proof

`pfr_add_addrs()` copies attacker-controlled `struct pfr_addr` entries from userland and creates kernel entries with attacker-selected `pfra_type`.

For `PFRKE_PLAIN`, `pfr_create_kentry_unlocked()` allocates from `pfr_kentry_pl[PFRKE_PLAIN]`, which is initialized as `sizeof(struct pfr_kentry)`. `PFRKE_COST` uses `sizeof(struct pfr_kentry_cost)` and contains the additional `weight` field.

During feedback handling, `pfr_add_addrs()` calls `pfr_fill_feedback()` and then immediately copies the populated `struct pfr_addr` back to the caller with `COPYOUT(&ad, addr+i, sizeof(ad), flags)`.

In `pfr_fill_feedback()`, the type switch breaks for `PFRKE_PLAIN` without setting a cost-specific weight, but the function then unconditionally executes:

```c
ad->pfra_weight = ((struct pfr_kentry_cost *)ke)->weight;
```

For a plain entry, this reads from the cost-only field beyond the plain allocation and places the resulting bytes in `ad.pfra_weight`, which is returned to userland.

## Why This Is A Real Bug

The allocation sizes are type-dependent, but the feedback path treats every entry as `struct pfr_kentry_cost` when reading `weight`.

`PFRKE_PLAIN` entries do not contain `struct pfr_kentry_cost::weight`. Therefore the unconditional cast and read accesses memory outside the valid plain-entry object. Because `pfr_add_addrs()` copies the resulting `struct pfr_addr` to userland under `PFR_FLAG_FEEDBACK`, the out-of-bounds read is externally observable as a kernel heap information disclosure.

## Fix Requirement

Only read `struct pfr_kentry_cost::weight` for `PFRKE_COST` entries. For non-cost entries, set `pfra_weight` explicitly to a safe default.

## Patch Rationale

The patch preserves the existing cost-entry behavior and avoids accessing cost-only storage for plain or route entries. Non-cost entries now return weight `1`, matching the existing default used elsewhere for non-cost table entries and weighted pool selection.

## Residual Risk

None

## Patch

```diff
diff --git a/net/pf_table.c b/net/pf_table.c
index 45c5533..a342530 100644
--- a/net/pf_table.c
+++ b/net/pf_table.c
@@ -299,7 +299,8 @@ pfr_fill_feedback(struct pfr_kentry_all *ke, struct pfr_addr *ad)
 	default:
 		unhandled_af(ke->pfrke_af);
 	}
-	ad->pfra_weight = ((struct pfr_kentry_cost *)ke)->weight;
+	ad->pfra_weight = (ke->pfrke_type == PFRKE_COST) ?
+	    ((struct pfr_kentry_cost *)ke)->weight : 1;
 	ad->pfra_af = ke->pfrke_af;
 	ad->pfra_net = ke->pfrke_net;
 	if (ke->pfrke_flags & PFRKE_FLAG_NOT)
```