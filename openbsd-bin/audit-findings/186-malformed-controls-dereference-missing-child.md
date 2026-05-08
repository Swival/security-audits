# Malformed Controls Dereference Missing Child

## Classification

Denial of service, medium severity. Confidence: certain.

## Affected Locations

`usr.sbin/ypldap/aldap.c:475`

## Summary

`aldap_parse()` treats any top-level LDAP message child with BER class `2` and type `0` as a paged-results control. Before the patch, it dereferenced `ep->be_sub->be_sub` without confirming either pointer existed. A malicious LDAP server can send a malformed SearchResultDone response with a context-specific `[0]` control missing nested children, causing a NULL pointer dereference and terminating `ypldap`.

## Provenance

Verified and reproduced from Swival Security Scanner results: https://swival.dev

## Preconditions

`ypldap` must parse a response from a malicious or compromised LDAP server.

## Proof

`aldap_parse()` handles `LDAP_RES_SEARCH_RESULT` and iterates `m->msg->be_sub`. For each top-level element, it reads the BER class and type:

```c
ober_scanf_elements(ep, "t", &class, &type);
if (class == 2 && type == 0)
	m->page = aldap_parse_page_control(ep->be_sub->be_sub,
	    ep->be_sub->be_sub->be_len);
```

The dereference assumes both `ep->be_sub` and `ep->be_sub->be_sub` are non-NULL.

A malformed SearchResultDone response can trigger the crash:

```text
30 10 02 01 01 65 07 0a 01 00 04 00 04 00 a0 02 30 00
```

The trailing bytes `a0 02 30 00` encode a context-specific `[0]` controls element containing an empty sequence. BER parsing creates `ep->be_sub`, but `ep->be_sub->be_sub` is `NULL`, so evaluating `ep->be_sub->be_sub->be_len` dereferences NULL.

The practical impact is daemon denial of service: the LDAP client process crashes, and the parent treats the lost child as fatal in `usr.sbin/ypldap/ypldap.c:78` and `usr.sbin/ypldap/ypldap.c:104`.

## Why This Is A Real Bug

The malformed control is fully server-controlled input. The parser reaches the vulnerable expression based only on BER class and type, not on the required nested structure. The reproducer demonstrates that valid BER encoding can produce a missing nested child and trigger the NULL dereference before `aldap_parse_page_control()` can validate anything.

## Fix Requirement

Validate `ep->be_sub` and `ep->be_sub->be_sub` before dereferencing them. Malformed controls must be ignored or rejected without crashing.

## Patch Rationale

The patch adds the required structural checks directly to the existing paged-control condition. `aldap_parse_page_control()` is only called when the control element has both expected child levels, preventing the NULL pointer dereference while preserving existing behavior for structurally valid controls.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/ypldap/aldap.c b/usr.sbin/ypldap/aldap.c
index 4efedbe..8240419 100644
--- a/usr.sbin/ypldap/aldap.c
+++ b/usr.sbin/ypldap/aldap.c
@@ -454,7 +454,8 @@ aldap_parse(struct aldap *ldap)
 		if (m->msg->be_sub) {
 			for (ep = m->msg->be_sub; ep != NULL; ep = ep->be_next) {
 				ober_scanf_elements(ep, "t", &class, &type);
-				if (class == 2 && type == 0)
+				if (class == 2 && type == 0 && ep->be_sub != NULL &&
+				    ep->be_sub->be_sub != NULL)
 					m->page = aldap_parse_page_control(ep->be_sub->be_sub,
 					    ep->be_sub->be_sub->be_len);
 			}
```