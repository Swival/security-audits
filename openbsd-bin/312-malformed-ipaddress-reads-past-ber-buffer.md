# malformed IpAddress reads past BER buffer

## Classification

out-of-bounds read

Severity: medium

Confidence: certain

## Affected Locations

`usr.bin/snmp/smi.c:375`

## Summary

`smi_print_element()` formats SNMP application `IpAddress` values by casting the decoded OCTET STRING buffer to `struct in_addr` and passing it to `inet_ntoa()`. It does this without verifying that the BER payload is exactly four octets. A malicious SNMP agent can return an application `IpAddress` element with a shorter length, causing the client to read past the BER buffer while formatting the response.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced with an ASan harness against the committed BER decoder.

## Preconditions

- Attacker controls or impersonates an SNMP agent responding to a normal client query.
- The response has matching protocol fields sufficient to reach client response formatting.
- The response contains an application class `IpAddress` OCTET STRING shorter than four octets.
- The client formats the returned element via `smi_print_element()`.

## Proof

A malformed BER element with bytes `40 01 7f` decodes as:

- class: application
- type: `SNMP_T_IPADDR`
- encoding: OCTET STRING
- length: 1
- payload: one octet

The reproduced execution path is:

- `usr.bin/snmp/snmpc.c:582` reaches `snmpc_print()`.
- `usr.bin/snmp/snmpc.c:1120` calls `smi_print_element()`.
- `usr.bin/snmp/smi.c:377` evaluates `inet_ntoa(*(struct in_addr *)buf)`.

Because `buf` contains only one decoded payload octet, dereferencing it as `struct in_addr` reads four bytes from a one-byte allocation. ASan reports a heap-buffer-overflow originating from the BER allocation at `lib/libutil/ber.c:1378`.

## Why This Is A Real Bug

`ober_get_string(root, &buf)` only confirms that the element has decodable string storage. It does not prove that an SNMP `IpAddress` value has the required IPv4 width.

SNMP `IpAddress` is application type 0 and must contain exactly four octets. The formatter assumes that invariant but response validation accepts the malformed value shape and does not check the value length. Therefore an attacker-controlled response can trigger an out-of-bounds read during normal client output formatting.

Impact is an attacker-triggered client crash under hardened or instrumented allocation, and possible disclosure of adjacent heap bytes through the printed dotted-quad address.

## Fix Requirement

Before calling `inet_ntoa()` for application `SNMP_T_IPADDR`, require:

```c
root->be_len == sizeof(struct in_addr)
```

Malformed `IpAddress` values with any other length must fail formatting.

## Patch Rationale

The patch adds a length check immediately before the unsafe cast and dereference. This preserves existing behavior for valid four-octet `IpAddress` values and rejects malformed BER payloads before reading beyond the decoded buffer.

The check is placed in the narrow `BER_CLASS_APPLICATION && SNMP_T_IPADDR` branch, so it does not affect ordinary OCTET STRING formatting, context exception strings, or display-hint handling.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/snmp/smi.c b/usr.bin/snmp/smi.c
index 5a29914..5028062 100644
--- a/usr.bin/snmp/smi.c
+++ b/usr.bin/snmp/smi.c
@@ -374,6 +374,8 @@ smi_print_element(struct ber_oid *oid, struct ber_element *root, int print_hint,
 			goto fail;
 		if (root->be_class == BER_CLASS_APPLICATION &&
 		    root->be_type == SNMP_T_IPADDR) {
+			if (root->be_len != sizeof(struct in_addr))
+				goto fail;
 			if (asprintf(&str, "%s%s",
 			    print_hint ? "IpAddress: " : "",
 			    inet_ntoa(*(struct in_addr *)buf)) == -1)
```