# Malformed Page Control Dereferences Missing Cookie Field

## Classification

Denial of service, medium severity.

## Affected Locations

`usr.bin/ldap/aldap.c:471`

## Summary

A malicious LDAP server can crash an LDAP client by returning a malformed paged-results response control whose encoded value contains the size element but omits the cookie element. `aldap_parse_page_control()` assumes the decoded control has both children and dereferences `elm->be_sub->be_next` without proving it exists.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The client parses an LDAP response received from a server socket or TLS stream.
- The response contains a top-level paged-results control.
- The paged-results control value is attacker-controlled and malformed.
- The decoded control value contains only the size INTEGER and omits the cookie OCTET STRING.

## Proof

`aldap_parse()` reads LDAP response bytes from the server and decodes them. For result messages, it walks response controls and calls `aldap_parse_page_control(ep->be_sub->be_sub, ...)` for a context-specific `[0]` controls element.

Inside `aldap_parse_page_control()`:

- `ober_read_elements(&b, NULL)` decodes the server-supplied encoded control value into `elm`.
- `ober_scanf_elements(elm->be_sub, "is", &page->size, &s)` attempts to parse an INTEGER and string, but its return value is ignored.
- The code immediately reads `elm->be_sub->be_next->be_len`.
- If the decoded value is a SEQUENCE containing only the size INTEGER, then `elm->be_sub` is non-NULL and `elm->be_sub->be_next` is NULL.
- Dereferencing `elm->be_sub->be_next->be_len` crashes the client process.

## Why This Is A Real Bug

The dereferenced structure is derived from untrusted LDAP server input. The reproducer confirms that a malformed paged-results control missing its cookie element reaches `aldap_parse_page_control()` and causes a NULL pointer dereference. LDAP paged-results controls are parsed during normal response handling, so a malicious or compromised LDAP server has a practical denial-of-service trigger against clients using this parser.

## Fix Requirement

Before dereferencing decoded page-control children, validate that:

- `elm` is non-NULL.
- `elm->be_sub` is non-NULL.
- `elm->be_sub->be_next` is non-NULL.

Malformed controls must be rejected cleanly by freeing allocated BER/page state and returning `NULL`.

## Patch Rationale

The patch adds a structural validation guard immediately after allocating `page` and before scanning or dereferencing decoded children. If the decoded BER tree lacks the expected sequence, first child, or cookie child, the function frees `elm`, frees the BER context, frees `page`, and returns `NULL`.

This directly prevents the crash at `elm->be_sub->be_next->be_len` while preserving existing successful parsing behavior for well-formed page controls.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/ldap/aldap.c b/usr.bin/ldap/aldap.c
index aee14a6..5e469e4 100644
--- a/usr.bin/ldap/aldap.c
+++ b/usr.bin/ldap/aldap.c
@@ -471,6 +471,13 @@ aldap_parse_page_control(struct ber_element *control, size_t len)
 		return NULL;
 	}
 
+	if (elm == NULL || elm->be_sub == NULL || elm->be_sub->be_next == NULL) {
+		if (elm != NULL)
+			ober_free_elements(elm);
+		ober_free(&b);
+		free(page);
+		return NULL;
+	}
 	ober_scanf_elements(elm->be_sub, "is", &page->size, &s);
 	page->cookie_len = elm->be_sub->be_next->be_len;
```