# Route Roaming Checks Wrong MAC Table

## Classification

Authorization bypass, medium severity.

## Affected Locations

`usr.sbin/hostapd/roaming.c:130`

## Summary

`hostapd_roaming()` enables route roaming only when `HOSTAPD_IAPP_F_ROAMING_ROUTE` is set and `i_route_tbl` exists, but the authorization lookup for that route operation incorrectly uses `i_addr_tbl`. A client MAC present only in the address table can therefore pass the route-roaming check and cause a privileged kernel route update despite not being authorized by the route table.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Route roaming is enabled.
- `i_route_tbl` is non-NULL.
- The attacker can associate or trigger roaming with a spoofed client MAC.
- The spoofed MAC exists in `i_addr_tbl` with `HOSTAPD_ENTRY_F_INADDR`.
- The spoofed MAC is absent from `i_route_tbl`.

## Proof

In `hostapd_roaming()`, the route-roaming block is gated by the route feature and route table:

```c
if (iapp->i_flags & HOSTAPD_IAPP_F_ROAMING_ROUTE &&
    iapp->i_route_tbl != NULL) {
```

However, the lookup inside that block uses the address table:

```c
entry = hostapd_entry_lookup(iapp->i_addr_tbl, node->ni_macaddr)
```

As reproduced, `stapd_apme_frame()` copies the associated station MAC into `node.ni_macaddr`, validates the node, and calls `hostapd_roaming_add()` when roaming is enabled. If the MAC exists only in `i_addr_tbl`, the lookup succeeds and the selected `entry->e_inaddr` is passed to `hostapd_roaming_rt()`.

With `add=true`, `hostapd_roaming_rt()` writes an `RTM_CHANGE` route message to `cfg->c_rtsock` and falls back to `RTM_ADD` on `ESRCH`, installing the route through the privileged route socket.

## Why This Is A Real Bug

The route-roaming code explicitly requires `i_route_tbl != NULL`, and `hostapd_roaming_term()` iterates `i_route_tbl` when deleting route-roaming entries. This establishes that `i_route_tbl` is the intended authorization source for route roaming.

Using `i_addr_tbl` instead allows an address-table entry to authorize a route-table operation. That bypasses the route table’s intended policy boundary and lets a spoofed MAC that is not present in `i_route_tbl` trigger an unauthorized kernel route installation.

## Fix Requirement

The route-roaming authorization lookup must use `iapp->i_route_tbl`, not `iapp->i_addr_tbl`.

## Patch Rationale

The patch changes only the table used by the route-roaming lookup. This aligns the lookup with:

- The enclosing `i_route_tbl != NULL` guard.
- The route-roaming feature flag.
- The route cleanup logic in `hostapd_roaming_term()`.
- The intended separation between address roaming and route roaming authorization.

No behavior changes are made to address roaming.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/hostapd/roaming.c b/usr.sbin/hostapd/roaming.c
index 4384895..a1e8367 100644
--- a/usr.sbin/hostapd/roaming.c
+++ b/usr.sbin/hostapd/roaming.c
@@ -128,7 +128,7 @@ hostapd_roaming(struct hostapd_apme *apme, struct hostapd_node *node, int add)
 
 	if (iapp->i_flags & HOSTAPD_IAPP_F_ROAMING_ROUTE &&
 	    iapp->i_route_tbl != NULL) {
-		if ((entry = hostapd_entry_lookup(iapp->i_addr_tbl,
+		if ((entry = hostapd_entry_lookup(iapp->i_route_tbl,
 		    node->ni_macaddr)) == NULL ||
 		    (entry->e_flags & HOSTAPD_ENTRY_F_INADDR) == 0)
 			return (ESRCH);
```