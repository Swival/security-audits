# Malformed Response Control Dereferences Missing Subelements

## Classification

denial of service, medium severity, certain confidence

## Affected Locations

`usr.bin/ldap/aldap.c:415`

## Summary

`aldap_parse()` trusts the BER shape of server-supplied LDAP response controls. When it sees a context-specific class `2`, type `0` element, it treats it as a paged results control and dereferences `ep->be_sub->be_sub` without first proving those subelements exist. A malicious LDAP server can send a malformed response control with missing nested BER elements and crash the client during parsing.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- The LDAP client parses a response from an attacker-controlled or malicious LDAP server.
- The attacker can send a malformed BER LDAP response containing a context-specific `[0]` control without the expected nested elements.

## Proof

The finding was reproduced from source behavior.

A server response such as:

```text
30 0e 02 01 01 65 07 0a 01 00 04 00 04 00 a0 00
```

is a BER LDAP `SearchResultDone` with a successful `LDAPResult` and an empty constructed context-specific `[0]` controls element.

Execution reaches the bug as follows:

- `aldap_parse()` reads server-controlled bytes from `ldap->fd` or TLS.
- `ober_read_elements()` decodes the BER message.
- The message enters the result-response case, including `LDAP_RES_SEARCH_RESULT`.
- The parser iterates `m->msg->be_sub`.
- For an element with class `2` and type `0`, the original code immediately evaluates `ep->be_sub->be_sub`.
- For the empty constructed `[0]` element, `ober_read_element()` leaves `be_sub == NULL`.
- The dereference occurs before `parsefail` can reject the malformed control, crashing the process.

## Why This Is A Real Bug

The input is attacker-controlled server data, not local trusted state. The parser explicitly accepts the response into its normal LDAP result handling path, identifies the malformed element as a response control by class and type, and then dereferences nested pointers that BER decoding may legitimately leave `NULL` for zero-length constructed elements. This creates a deterministic NULL pointer crash and therefore an attacker-triggered denial of service.

## Fix Requirement

Validate that `ep->be_sub` and `ep->be_sub->be_sub` are non-NULL before dereferencing them. Malformed controls that lack required nested elements must be rejected through the existing parser failure path.

## Patch Rationale

The patch adds a structural guard immediately before the vulnerable dereference:

```c
if (ep->be_sub == NULL || ep->be_sub->be_sub == NULL)
	goto parsefail;
```

This preserves the existing behavior for well-formed paged results controls while routing malformed controls to the established `parsefail` handling. `parsefail` drains the input buffer, sets `ldap->err = ALDAP_ERR_PARSER_ERROR`, frees the partially parsed message, and returns `NULL` instead of crashing.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/ldap/aldap.c b/usr.bin/ldap/aldap.c
index aee14a6..817c4a5 100644
--- a/usr.bin/ldap/aldap.c
+++ b/usr.bin/ldap/aldap.c
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