# page control parser dereferences absent value

## Classification

denial of service, medium severity

## Affected Locations

`usr.sbin/ypldap/aldap.c:516`

## Summary

`aldap_parse_page_control()` parses LDAP paged-results controls but assumes the optional `controlValue` element is present. A malicious LDAP server can return a paged-results control containing only the OID. The parser then dereferences `control->be_next->be_len` while `control->be_next` is `NULL`, causing a SIGSEGV and terminating `ypldap`.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

Confidence: certain

## Preconditions

- `ypldap` parses LDAP search result controls.
- The LDAP server response is attacker-controlled or comes from a malicious LDAP server.
- The search result includes a context-specific control for paged results.
- The control sequence omits the encoded page-control value.

## Proof

The vulnerable path is:

```c
ober_scanf_elements(control, "ss", &oid, &encoded);
ober_set_readbuf(&b, encoded, control->be_next->be_len);
```

`ober_scanf_elements(control, "ss", ...)` is not checked. If the BER control sequence contains only:

```text
Control ::= SEQUENCE {
  controlType OCTET STRING "1.2.840.113556.1.4.319"
}
```

then the BER reader creates a first child for the OID and no `be_next` value element. The unchecked parse failure is ignored, and `control->be_next->be_len` dereferences `NULL`.

Concrete trigger shape:

```text
30 28
  02 01 01
  65 07 0a 01 00 04 00 04 00
  a0 1a
    30 18
      04 16 31 2e 32 2e 38 34 30 2e 31 31 33 35 35 36 2e 31 2e 34 2e 33 31 39
```

The practical impact is process-level denial of service: the LDAP client child dies from SIGSEGV, and the parent exits after observing the lost child.

## Why This Is A Real Bug

LDAP controls may be malformed or intentionally incomplete when received from an untrusted server. The code handles a network-originated BER structure but assumes a sibling element exists without validating it. The BER reader only links `be_next` when another element remains in the sequence, so an OID-only control reliably reaches a `NULL` dereference before any validation can reject the message.

## Fix Requirement

The parser must reject malformed page controls before reading the encoded value length. Specifically, it must require:

- successful scan of both expected string elements
- non-`NULL` `control->be_next`

## Patch Rationale

The patch adds validation immediately after `ober_scanf_elements()`:

```c
if (ober_scanf_elements(control, "ss", &oid, &encoded) != 0 ||
    control->be_next == NULL)
	return NULL;
```

This preserves existing parsing behavior for valid controls and converts malformed controls into a clean parse failure. It prevents `ober_set_readbuf()` from receiving a missing value element and prevents dereferencing `control->be_next` when absent.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/ypldap/aldap.c b/usr.sbin/ypldap/aldap.c
index 4efedbe..81210e9 100644
--- a/usr.sbin/ypldap/aldap.c
+++ b/usr.sbin/ypldap/aldap.c
@@ -496,7 +496,9 @@ aldap_parse_page_control(struct ber_element *control, size_t len)
 	struct aldap_page_control *page;
 
 	b.br_wbuf = NULL;
-	ober_scanf_elements(control, "ss", &oid, &encoded);
+	if (ober_scanf_elements(control, "ss", &oid, &encoded) != 0 ||
+	    control->be_next == NULL)
+		return NULL;
 	ober_set_readbuf(&b, encoded, control->be_next->be_len);
 	elm = ober_read_elements(&b, NULL);
```