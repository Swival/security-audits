# legacy SNMP IPADDR formatter reads past short BER string

## Classification

Out-of-bounds read, medium severity. Confidence: certain.

## Affected Locations

`usr.sbin/snmpd/smi.c:406`

## Summary

`smi_print_element_legacy()` formats application-class `SNMP_T_IPADDR` BER values by retrieving an OCTET STRING buffer and immediately casting it to `struct in_addr`. The function did not verify that the BER string length was exactly four bytes before dereferencing the cast pointer. A malformed IpAddress value with a short payload can therefore make the formatter read past the returned buffer while producing the legacy IP address string.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- Legacy formatting is reached for an attacker-controlled BER application IpAddress element.
- A remote SNMP peer can send an accepted crafted trap packet.
- A matching `trap handle` configuration causes trap varbinds to be formatted with `smi_print_element_legacy()`.

## Proof

The vulnerable branch is in `smi_print_element_legacy()`:

```c
case BER_TYPE_OCTETSTRING:
	if (ober_get_string(root, &buf) == -1)
		goto fail;
	if (root->be_class == BER_CLASS_APPLICATION &&
	    root->be_type == SNMP_T_IPADDR) {
		if (asprintf(&str, "%s",
		    inet_ntoa(*(struct in_addr *)buf)) == -1)
			goto fail;
	}
```

`ober_get_string(root, &buf)` returns the string buffer, but the formatter did not check `root->be_len` before evaluating:

```c
*(struct in_addr *)buf
```

For an application-class `SNMP_T_IPADDR` value whose BER payload is shorter than `sizeof(struct in_addr)`, this dereference reads bytes beyond the valid BER string payload.

The reproduced trigger path is trap handling:

- Accepted SNMPv1/SNMPv2c trap packets reach `traphandler_parse()`.
- Trap varbind structure is validated, but application IpAddress length is not validated at `usr.sbin/snmpd/traphandler.c:97` and `usr.sbin/snmpd/traphandler.c:104`.
- With a matching `trap handle`, `trapcmd_exec()` formats each varbind through `smi_print_element_legacy()` at `usr.sbin/snmpd/traphandler.c:379` and `usr.sbin/snmpd/traphandler.c:382`.
- The resulting formatted value is written to the configured handler stdin at `usr.sbin/snmpd/traphandler.c:385`.

The reproducer confirmed the short-string out-of-bounds read. It also narrowed the original “under four bytes” phrasing: some lengths may read the BER helper’s NUL terminator, but the short-string OOB read remains directly present.

## Why This Is A Real Bug

SNMP IpAddress values are four-byte IPv4 addresses. The formatter assumes that invariant but processes BER input that can carry a shorter OCTET STRING. Casting and dereferencing `buf` as `struct in_addr` without checking `root->be_len` makes the read size fixed at four bytes regardless of the actual payload length. Because the formatted result is delivered to the configured trap handler, adjacent process memory can influence the emitted legacy IP address string.

## Fix Requirement

Before casting the BER string buffer to `struct in_addr`, require:

```c
root->be_len == sizeof(struct in_addr)
```

Malformed IpAddress values with any other length must fail formatting instead of being dereferenced.

## Patch Rationale

The patch adds the missing length check immediately before the unsafe cast in the legacy IpAddress branch:

```diff
 if (root->be_class == BER_CLASS_APPLICATION &&
     root->be_type == SNMP_T_IPADDR) {
+	if (root->be_len != sizeof(struct in_addr))
+		goto fail;
 	if (asprintf(&str, "%s",
 	    inet_ntoa(*(struct in_addr *)buf)) == -1)
 		goto fail;
```

This preserves existing behavior for valid four-byte IpAddress values and rejects malformed BER strings before any fixed-width load occurs.

## Residual Risk

None

## Patch

`253-legacy-snmp-ipaddr-formatter-reads-past-short-ber-string.patch`

```diff
diff --git a/usr.sbin/snmpd/smi.c b/usr.sbin/snmpd/smi.c
index 0385b32..35022eb 100644
--- a/usr.sbin/snmpd/smi.c
+++ b/usr.sbin/snmpd/smi.c
@@ -403,6 +403,8 @@ smi_print_element_legacy(struct ber_element *root)
 			goto fail;
 		if (root->be_class == BER_CLASS_APPLICATION &&
 		    root->be_type == SNMP_T_IPADDR) {
+			if (root->be_len != sizeof(struct in_addr))
+				goto fail;
 			if (asprintf(&str, "%s",
 			    inet_ntoa(*(struct in_addr *)buf)) == -1)
 				goto fail;
```