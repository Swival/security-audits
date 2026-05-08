# Flowspec routes bypass filters

## Classification

Security control failure, high severity, certain confidence.

## Affected Locations

`usr.sbin/bgpd/rde_filter.c:1115`

`usr.sbin/bgpd/rde_filter.c:1172`

## Summary

`rde_filter()` and `rde_filter_out()` unconditionally returned `ACTION_ALLOW` for `AID_FLOWSPECv4` and `AID_FLOWSPECv6` before evaluating configured filter rules. This caused flowspec routes to bypass deny rules and fail open instead of enforcing the normal default-deny and rule-evaluation behavior.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- A caller invokes `rde_filter()` or `rde_filter_out()`.
- The supplied prefix has `prefix->aid == AID_FLOWSPECv4` or `prefix->aid == AID_FLOWSPECv6`.
- Configured filter rules are expected to reject the route.

## Proof

Both filter entry points initialize the decision to default deny:

```c
enum filter_action action = ACTION_DENY; /* default deny */
```

Before rule evaluation, both functions returned allow for flowspec prefixes:

```c
if (prefix->aid == AID_FLOWSPECv4 || prefix->aid == AID_FLOWSPECv6)
	return (ACTION_ALLOW);
```

This was present in:

- `rde_filter()` at `usr.sbin/bgpd/rde_filter.c:1118`
- `rde_filter_out()` at `usr.sbin/bgpd/rde_filter.c:1175`

As a result, an otherwise matching deny rule, including an any-match deny, was never consulted for flowspec input.

The concretely reproduced path is outbound/local flowspec dissemination:

- Configured flowspecs are added through `flowspec_add()` at `usr.sbin/bgpd/rde.c:4855`.
- They are stored in `flowrib` by `prefix_flowspec_update()` at `usr.sbin/bgpd/rde_rib.c:1016`.
- Peer dissemination reaches `rde_filter_out()` from `usr.sbin/bgpd/rde_update.c:180`.
- `rde_filter_out()` then returned `ACTION_ALLOW` before evaluating configured outbound filters.

The inbound-from-remote framing is broader than the currently proven code path because received flowspec NLRIs are skipped before normal import filtering at `usr.sbin/bgpd/rde.c:1900`. The reproduced bug is the deterministic filter-control fail-open for flowspec prefixes, concretely reachable on outbound flowspec announcements.

## Why This Is A Real Bug

The filter functions implement BGP route filter decisions and explicitly default to `ACTION_DENY`. Their intended behavior is to evaluate configured rules through `rde_filter_match()` and apply matching actions.

The flowspec shortcut bypassed that policy engine entirely. Therefore, configured deny rules were ineffective for flowspec prefixes, which is a direct failure of the route-filter security control.

## Fix Requirement

Remove the special-case flowspec allow path so flowspec prefixes are evaluated by the same configured filter rules as other prefixes.

## Patch Rationale

The patch deletes the unconditional `ACTION_ALLOW` returns from both `rde_filter()` and `rde_filter_out()`.

After the change:

- Parse-error handling still denies malformed updates.
- `rde_filter()` still returns default deny when no rules exist.
- Flowspec prefixes enter the normal rule loop.
- Matching deny rules can reject flowspec routes.
- Matching allow rules can still permit flowspec routes intentionally.
- If no rule allows the route, the existing default-deny behavior applies.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/bgpd/rde_filter.c b/usr.sbin/bgpd/rde_filter.c
index 6520629..3776a7e 100644
--- a/usr.sbin/bgpd/rde_filter.c
+++ b/usr.sbin/bgpd/rde_filter.c
@@ -1115,9 +1115,6 @@ rde_filter(struct filter_head *rules, struct rde_peer *peer,
 	if (rules == NULL)
 		return (action);
 
-	if (prefix->aid == AID_FLOWSPECv4 || prefix->aid == AID_FLOWSPECv6)
-		return (ACTION_ALLOW);
-
 	f = TAILQ_FIRST(rules);
 	while (f != NULL) {
 		if (f->peer.peerid && f->peer.peerid != peer->conf.id) {
@@ -1172,9 +1169,6 @@ rde_filter_out(struct rde_filter *rf, struct rde_peer *peer,
 		 */
 		return (ACTION_DENY);
 
-	if (prefix->aid == AID_FLOWSPECv4 || prefix->aid == AID_FLOWSPECv6)
-		return (ACTION_ALLOW);
-
 	for (i = 0; i < rf->len; i++) {
 		f = &rf->rules[i];
 		if (rde_filter_match(&f->match, peer, from, state,
```