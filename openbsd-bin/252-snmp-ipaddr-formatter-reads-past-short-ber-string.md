# SNMP IPADDR formatter reads past short BER string

## Classification

Out-of-bounds read. Severity: medium. Confidence: certain.

## Affected Locations

`usr.sbin/snmpd/smi.c:489`

## Summary

`smi_print_element()` formats application-class `SNMP_T_IPADDR` values by retrieving a BER string pointer and casting it directly to `struct in_addr`. The code did not verify that the BER string length was exactly four bytes before the load. A crafted SNMP IPADDR element with `be_len` under four bytes can cause the formatter to read adjacent daemon memory while producing the dotted-quad string.

## Provenance

Verified and reproduced from the supplied finding. Scanner provenance: https://swival.dev

## Preconditions

- A crafted BER element reaches `smi_print_element()` for logging or display.
- The element is `BER_CLASS_APPLICATION` with type `SNMP_T_IPADDR`.
- The decoded BER string length is shorter than `sizeof(struct in_addr)`.

## Proof

The vulnerable path in `usr.sbin/snmpd/smi.c` handled `BER_CLASS_APPLICATION` / `SNMP_T_IPADDR` as follows:

```c
if (ober_get_string(root, &buf) == -1)
	goto fail;
if (asprintf(&str, "%s",
    inet_ntoa(*(struct in_addr *)buf)) == -1)
		goto fail;
```

`ober_get_string()` returns the decoded string buffer, but this path did not check `root->be_len` before dereferencing `buf` as a four-byte `struct in_addr`.

The reproducer confirmed:

- `ober_get_string()` only validates OCTET STRING encoding.
- BER decoding allocates only `len + 1` bytes.
- Crafted IPADDR lengths of 0, 1, or 2 bytes cause an actual heap out-of-bounds read during the four-byte load.
- Length 3 reads the decoder-added NUL terminator but does not read past the allocation.
- A normal remote trap path can reach the formatter through trap handling and write the formatted dotted-quad into trap handler input.

## Why This Is A Real Bug

SNMP IPADDR values are four-byte IPv4 addresses. The formatter assumes this invariant but accepts the BER string pointer without enforcing the required length. Since the BER decoder can produce shorter allocations for malformed input, the cast and dereference read beyond the object boundary. The resulting bytes are then passed to `inet_ntoa()` and included in formatted output, creating an information disclosure across the intended BER value boundary.

## Fix Requirement

Require `root->be_len == sizeof(struct in_addr)` before casting the BER string buffer to `struct in_addr`.

## Patch Rationale

The patch rejects malformed IPADDR elements whose decoded BER payload is not exactly four bytes. This preserves valid IPv4 formatting behavior while preventing short buffers from being read as a full `struct in_addr`.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/snmpd/smi.c b/usr.sbin/snmpd/smi.c
index 0385b32..5c915a0 100644
--- a/usr.sbin/snmpd/smi.c
+++ b/usr.sbin/snmpd/smi.c
@@ -486,6 +486,8 @@ smi_print_element(struct ber_element *root)
 		case SNMP_T_IPADDR:
 			if (ober_get_string(root, &buf) == -1)
 				goto fail;
+			if (root->be_len != sizeof(struct in_addr))
+				goto fail;
 			if (asprintf(&str, "%s",
 			    inet_ntoa(*(struct in_addr *)buf)) == -1)
 					goto fail;
```