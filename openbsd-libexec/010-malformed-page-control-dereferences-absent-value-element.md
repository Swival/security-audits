# Malformed Page Control Dereferences Absent Value Element

## Classification

Denial of service, medium severity.

Confidence: certain.

## Affected Locations

`login_ldap/aldap.c:376`

Patch location: `login_ldap/aldap.c:460`

## Summary

`aldap_parse_page_control()` assumes an LDAP page response control contains both an OID and an encoded value. A malicious LDAP server can send a control sequence containing only the OID. The parser then dereferences `control->be_next` even though it is `NULL`, crashing the `login_ldap` authentication helper.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched from the provided scanner result, reproducer summary, affected source, and patch.

## Preconditions

- The client parses LDAP response controls from an attacker-controlled LDAP server.
- The LDAP response includes a context-specific response controls element.
- The first Control sequence contains a `controlType` / OID element but no encoded value element.

## Proof

`aldap_parse()` walks decoded LDAP message children and treats context-specific tag `0` as response controls. It passes the first element inside the first Control sequence to `aldap_parse_page_control()`.

For a malformed Control sequence containing only the OID:

- `control` points to the OID element.
- `control->be_next == NULL` because no value element follows.
- `ober_scanf_elements(control, "ss", &oid, &encoded)` fails because the second string is absent.
- The return value is ignored in the vulnerable version.
- `ober_set_readbuf(&b, encoded, control->be_next->be_len)` immediately dereferences `control->be_next`.
- The authentication helper crashes before parser error handling can recover.

This path is reachable during authentication because LDAP bind and search response handling call `aldap_parse()` on server replies.

## Why This Is A Real Bug

The crash is caused by a direct unchecked NULL dereference on attacker-controlled input. LDAP response controls are parsed from the server response, and a malicious LDAP peer can legally shape the BER structure such that the Control sequence has an OID but lacks the expected value element.

The vulnerable code depends on `ober_scanf_elements()` succeeding but does not verify that result. It also assumes `control->be_next` exists before reading `control->be_next->be_len`. The reproducer confirms that omitting the value element makes `control->be_next == NULL` and terminates the helper.

## Fix Requirement

Validate that the page control contains the expected encoded value before using it:

- Check the return value of `ober_scanf_elements(control, "ss", &oid, &encoded)`.
- Check that `control->be_next` is not `NULL`.
- Return parser failure for malformed controls instead of dereferencing absent elements.

## Patch Rationale

The patch adds a guard before `ober_set_readbuf()`:

```c
if (ober_scanf_elements(control, "ss", &oid, &encoded) != 0 ||
    control->be_next == NULL)
	return NULL;
```

This prevents use of an uninitialized or absent `encoded` value and prevents dereferencing `control->be_next` when the BER element is missing. Returning `NULL` matches existing failure behavior for page control parsing and converts the malformed input from a process crash into a handled parse failure.

## Residual Risk

None

## Patch

```diff
diff --git a/login_ldap/aldap.c b/login_ldap/aldap.c
index d5f5769..29f9821 100644
--- a/login_ldap/aldap.c
+++ b/login_ldap/aldap.c
@@ -460,7 +460,9 @@ aldap_parse_page_control(struct ber_element *control, size_t len)
 	struct aldap_page_control *page;
 
 	b.br_wbuf = NULL;
-	ober_scanf_elements(control, "ss", &oid, &encoded);
+	if (ober_scanf_elements(control, "ss", &oid, &encoded) != 0 ||
+	    control->be_next == NULL)
+		return NULL;
 	ober_set_readbuf(&b, encoded, control->be_next->be_len);
 	elm = ober_read_elements(&b, NULL);
```
