# invalid page control BER dereferences null parse tree

## Classification

Denial of service, medium severity, confidence certain.

## Affected Locations

`usr.sbin/ypldap/aldap.c:527`

## Summary

`ypldap` can crash when parsing a paged LDAP search response from a malicious LDAP server. The response control value is attacker-controlled BER. If that value is empty or malformed, `ober_read_elements()` returns `NULL`, but `aldap_parse_page_control()` dereferences the returned parse tree without validating it.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- `ypldap` accepts a paged search response from an attacker-controlled LDAP server.
- The LDAP response contains a paged-results response control.
- The control value is empty or malformed BER.

## Proof

Reachability is established through `client_search_idm()` sending paged searches and then calling `aldap_parse()` on server-controlled responses in `usr.sbin/ypldap/ldapclient.c:520`.

For search result responses, `aldap_parse()` walks response controls and calls `aldap_parse_page_control(ep->be_sub->be_sub, ...)` for context-specific `[0]` controls in `usr.sbin/ypldap/aldap.c:455`.

Inside `aldap_parse_page_control()`, the attacker-controlled control value is installed as a BER read buffer and decoded:

```c
ober_set_readbuf(&b, encoded, control->be_next->be_len);
elm = ober_read_elements(&b, NULL);
```

For an empty control value, the read buffer length is 0 and `ober_read_elements()` returns `NULL`.

The original code then immediately dereferences the parse tree:

```c
ober_scanf_elements(elm->be_sub, "is", &page->size, &s);
page->cookie_len = elm->be_sub->be_next->be_len;
```

This causes a NULL pointer dereference and terminates `ypldap`.

## Why This Is A Real Bug

The decoded BER tree is derived directly from server-controlled LDAP response data. Invalid or empty BER is a valid adversarial input, and `ober_read_elements()` can return `NULL` for that input. The caller assumes a non-NULL tree with at least two child elements, so malformed input deterministically reaches a NULL pointer dereference instead of being rejected as a parse error.

## Fix Requirement

Reject decoded page-control BER when:

- `ober_read_elements()` returns `NULL`.
- The decoded root has no child element.
- The decoded child list is missing the cookie element required before `elm->be_sub->be_next` is read.

## Patch Rationale

The patch adds structural validation immediately after BER decoding and before allocation or dereference:

```diff
+	if (elm == NULL || elm->be_sub == NULL ||
+	    elm->be_sub->be_next == NULL) {
+		if (elm != NULL)
+			ober_free_elements(elm);
+		ober_free(&b);
+		return NULL;
+	}
```

This converts malformed page-control BER into a clean parse failure path. It also frees any partially decoded BER tree and the local BER buffer before returning, preserving existing ownership behavior.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/ypldap/aldap.c b/usr.sbin/ypldap/aldap.c
index 4efedbe..da6ee8a 100644
--- a/usr.sbin/ypldap/aldap.c
+++ b/usr.sbin/ypldap/aldap.c
@@ -499,6 +499,13 @@ aldap_parse_page_control(struct ber_element *control, size_t len)
 	ober_scanf_elements(control, "ss", &oid, &encoded);
 	ober_set_readbuf(&b, encoded, control->be_next->be_len);
 	elm = ober_read_elements(&b, NULL);
+	if (elm == NULL || elm->be_sub == NULL ||
+	    elm->be_sub->be_next == NULL) {
+		if (elm != NULL)
+			ober_free_elements(elm);
+		ober_free(&b);
+		return NULL;
+	}
 
 	if ((page = malloc(sizeof(struct aldap_page_control))) == NULL) {
 		if (elm != NULL)
```