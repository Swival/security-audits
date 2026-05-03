# Malformed LDAP Control Dereferences Missing Child Elements

## Classification

Denial of service, medium severity.

## Affected Locations

`login_ldap/aldap.c:422`

## Summary

`aldap_parse()` parses LDAP result controls from server-supplied BER data and assumes a context-specific `[0]` control element always contains nested child elements. A malformed LDAP response control with missing children causes `ep->be_sub->be_sub` to dereference `NULL`, terminating the authentication helper instead of returning a parser error.

## Provenance

Verified from supplied source, reproduced behavior, and patch evidence.

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- `login_ldap` parses an LDAP result message containing controls.
- The LDAP response is supplied by a malicious or compromised LDAP server/backend.
- A result message such as `LDAP_RES_BIND` or `LDAP_RES_SEARCH_RESULT` includes a context-specific class `2`, type `0` control element with missing nested child elements.

## Proof

`aldap_parse()` reads LDAP server data from `ldap->fd` or TLS into `ldap->buf`, then parses it with `ober_read_elements()`.

For LDAP result messages, it iterates children of `m->msg->be_sub` and treats any element where `ober_scanf_elements(ep, "t", &class, &type)` yields `class == 2 && type == 0` as controls.

The vulnerable code dereferences both levels without validation:

```c
m->page = aldap_parse_page_control(ep->be_sub->be_sub,
    ep->be_sub->be_sub->be_len);
```

A malicious LDAP server can send a valid-looking BindResponse or SearchResult followed by an empty controls element, for example a trailing `a0 00`. That produces a context-specific class/type `0` element with no children, so `ep->be_sub == NULL`. The next dereference crashes the process before parse failure handling can run.

## Why This Is A Real Bug

The input is server-controlled BER read directly from the LDAP connection. The parser already accepts the outer LDAP message shape and reaches the controls loop. The control branch checks only the tag class and type, not the required child structure, so malformed but parseable BER reaches an unconditional `NULL` dereference.

Impact is authentication-helper process termination, allowing a malicious LDAP peer/backend to deny LDAP-backed authentication attempts.

## Fix Requirement

Before dereferencing `ep->be_sub->be_sub`, validate that:

- `ep->be_sub != NULL`
- `ep->be_sub->be_sub != NULL`

Malformed controls must be rejected through the existing parse failure path rather than dereferenced.

## Patch Rationale

The patch adds structural validation immediately inside the `class == 2 && type == 0` branch. If either required child pointer is absent, execution jumps to `parsefail`, which drains the input buffer, sets `ldap->err = ALDAP_ERR_PARSER_ERROR`, frees the partially parsed message, and returns `NULL`.

This preserves existing behavior for well-formed page controls while converting malformed controls from a crash into a parser error.

## Residual Risk

None

## Patch

```diff
diff --git a/login_ldap/aldap.c b/login_ldap/aldap.c
index d5f5769..3989cce 100644
--- a/login_ldap/aldap.c
+++ b/login_ldap/aldap.c
@@ -418,9 +418,12 @@ aldap_parse(struct aldap *ldap)
 		if (m->msg->be_sub) {
 			for (ep = m->msg->be_sub; ep != NULL; ep = ep->be_next) {
 				ober_scanf_elements(ep, "t", &class, &type);
-				if (class == 2 && type == 0)
+				if (class == 2 && type == 0) {
+					if (ep->be_sub == NULL || ep->be_sub->be_sub == NULL)
+						goto parsefail;
 					m->page = aldap_parse_page_control(ep->be_sub->be_sub,
 					    ep->be_sub->be_sub->be_len);
+				}
 			}
 		} else
 			m->page = NULL;
```