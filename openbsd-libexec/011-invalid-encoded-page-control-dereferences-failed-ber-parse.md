# Invalid Encoded Page Control Dereferences Failed BER Parse

## Classification

Denial of service, medium severity.

Confidence: certain.

## Affected Locations

`login_ldap/aldap.c:386`

`login_ldap/aldap.c:421`

`login_ldap/aldap.c:465`

`login_ldap/aldap.c:474`

`login_ldap/aldap.c:475`

## Summary

`login_ldap` requests paged LDAP results, then parses the server-supplied paged-results control without validating that the encoded control value is the required BER sequence.

A malicious LDAP server can return an invalid paged-results `controlValue`, causing `aldap_parse_page_control()` to dereference `elm->be_sub` when it is `NULL`. The authentication helper terminates, producing an attacker-triggered denial of service.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched from the supplied evidence.

## Preconditions

`login_ldap` requests paged LDAP results from an attacker-controlled LDAP server.

## Proof

`aldap_parse()` processes LDAP result messages and, for context control type `0`, calls:

```c
m->page = aldap_parse_page_control(ep->be_sub->be_sub,
    ep->be_sub->be_sub->be_len);
```

`aldap_parse_page_control()` then treats the server-supplied `controlValue` as nested BER:

```c
ober_set_readbuf(&b, encoded, control->be_next->be_len);
elm = ober_read_elements(&b, NULL);
```

Before the patch, the code immediately used:

```c
ober_scanf_elements(elm->be_sub, "is", &page->size, &s);
page->cookie_len = elm->be_sub->be_next->be_len;
```

A malicious server can send a valid LDAP `SearchResultDone` containing a paged-results control whose `controlValue` is BER for a primitive integer, such as:

```text
02 01 00
```

That value is valid BER but not the required paged-results sequence. `ober_read_elements()` can return a non-`NULL` element with no `be_sub`. The subsequent `elm->be_sub` and `elm->be_sub->be_next` accesses dereference a null pointer.

## Why This Is A Real Bug

The vulnerable data is supplied by the LDAP peer/backend, which may be attacker-controlled under the stated precondition.

The parser accepts the outer LDAP response far enough to reach paged-results control handling. The malformed inner `controlValue` does not need to corrupt memory or violate transport framing; it only needs to be the wrong BER shape. The original code assumes the parsed element has the expected children and dereferences them unconditionally.

The reproduced crash path is therefore a direct null-pointer dereference reachable from a malicious LDAP response, causing denial of service.

## Fix Requirement

Validate the result of `ober_read_elements()` before dereferencing it.

Specifically, reject the paged-results control if:

- BER parsing returns `NULL`
- the parsed element has no first child
- the first child has no following cookie element
- `ober_scanf_elements()` fails to parse the expected size and cookie fields

## Patch Rationale

The patch adds structural validation immediately after decoding the nested control value:

```c
if (elm == NULL || elm->be_sub == NULL ||
    elm->be_sub->be_next == NULL) {
```

This prevents dereferencing `elm`, `elm->be_sub`, or `elm->be_sub->be_next` unless the minimum expected BER structure exists.

The patch also checks the return value of:

```c
ober_scanf_elements(elm->be_sub, "is", &page->size, &s)
```

If the decoded children are present but not parseable as the expected integer/string tuple, the function now frees allocated state and returns `NULL` instead of continuing with invalid assumptions.

Invalid paged-results controls are therefore treated as parse failures for that optional control rather than process-terminating crashes.

## Residual Risk

None

## Patch

```diff
diff --git a/login_ldap/aldap.c b/login_ldap/aldap.c
index d5f5769..2fe61c1 100644
--- a/login_ldap/aldap.c
+++ b/login_ldap/aldap.c
@@ -463,6 +463,13 @@ aldap_parse_page_control(struct ber_element *control, size_t len)
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
@@ -471,7 +478,12 @@ aldap_parse_page_control(struct ber_element *control, size_t len)
 		return NULL;
 	}
 
-	ober_scanf_elements(elm->be_sub, "is", &page->size, &s);
+	if (ober_scanf_elements(elm->be_sub, "is", &page->size, &s) != 0) {
+		ober_free_elements(elm);
+		ober_free(&b);
+		free(page);
+		return NULL;
+	}
 	page->cookie_len = elm->be_sub->be_next->be_len;
 
 	if ((page->cookie = malloc(page->cookie_len)) == NULL) {
```