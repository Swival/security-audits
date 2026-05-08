# flowspec routes bypass outbound filters

## Classification

security_control_failure, high severity, confidence certain

## Affected Locations

`usr.sbin/bgpd/rde_filter.c:1172`

## Summary

`rde_filter_out()` implements outbound BGP export filtering, but it unconditionally allowed `AID_FLOWSPECv4` and `AID_FLOWSPECv6` before evaluating configured export rules. As a result, outbound deny rules were skipped for flowspec NLRI and rejected flowspec routes could be exported.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

## Preconditions

- Caller invokes `rde_filter_out()` with `prefix->aid == AID_FLOWSPECv4` or `prefix->aid == AID_FLOWSPECv6`.
- An outbound filter rule exists that should reject the flowspec route.
- The peer/session path supports flowspec and is not otherwise blocked before `rde_filter_out()`.

## Proof

`rde_filter_out()` denies parse-error paths, then immediately returned `ACTION_ALLOW` for flowspec address families before entering the rule loop.

The bypass occurred here:

```c
if (prefix->aid == AID_FLOWSPECv4 || prefix->aid == AID_FLOWSPECv6)
	return (ACTION_ALLOW);
```

Because this return happened before iterating `rf->rules`, no configured outbound rule could run. A deny-all outbound rule would otherwise match because `rde_filter_match()` returns true for an empty/any match. Therefore a flowspec route that should be denied by export policy was deterministically allowed.

The route is practically exportable: local/configured flowspecs are inserted through `flowspec_add()` and `prefix_flowspec_update()`, update generation reaches `rde_filter_out()`, and after the forced allow the route can proceed to `adjout_prefix_update()` for export.

## Why This Is A Real Bug

Outbound filters are the security and policy control for BGP export decisions. `rde_filter_out()` is the export-filter decision point, but the flowspec special case bypassed rule evaluation entirely. This makes configured reject policies ineffective for flowspec routes while non-flowspec routes remain subject to the same rule loop.

The behavior is fail-open: a route that the administrator configured to deny is exported solely because its address family is `AID_FLOWSPECv4` or `AID_FLOWSPECv6`.

## Fix Requirement

Remove the unconditional flowspec allow from `rde_filter_out()`, or otherwise ensure outbound deny rules are evaluated before any flowspec allow decision.

## Patch Rationale

The patch removes the early `ACTION_ALLOW` return for `AID_FLOWSPECv4` and `AID_FLOWSPECv6` in `rde_filter_out()`.

After the patch, flowspec routes follow the same outbound rule evaluation path as other exported routes:

- parse-error paths remain denied;
- each cached outbound rule in `rf->rules` is evaluated;
- matching rules can apply filter sets;
- deny actions and quick rules are honored;
- default behavior remains `ACTION_DENY` if no rule allows the route.

This restores outbound policy enforcement without changing parse-error handling or the existing rule loop semantics.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/bgpd/rde_filter.c b/usr.sbin/bgpd/rde_filter.c
index 6520629..97052ff 100644
--- a/usr.sbin/bgpd/rde_filter.c
+++ b/usr.sbin/bgpd/rde_filter.c
@@ -1172,9 +1172,6 @@ rde_filter_out(struct rde_filter *rf, struct rde_peer *peer,
 		 */
 		return (ACTION_DENY);
 
-	if (prefix->aid == AID_FLOWSPECv4 || prefix->aid == AID_FLOWSPECv6)
-		return (ACTION_ALLOW);
-
 	for (i = 0; i < rf->len; i++) {
 		f = &rf->rules[i];
 		if (rde_filter_match(&f->match, peer, from, state,
```