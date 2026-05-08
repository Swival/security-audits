# Padded AgentX String Length Advances Past PDU

## Classification

High severity out-of-bounds read.

Confidence: certain.

## Affected Locations

`usr.sbin/snmpd/ax.c:1056`

Primary vulnerable parser:

`usr.sbin/snmpd/ax.c:1410`

Confirmed downstream out-of-bounds read:

`usr.sbin/snmpd/ax.c:245`

## Summary

`ax_pdutoostring()` validates that the declared AgentX string length fits in the remaining raw payload, but it does not validate that the required 4-byte-aligned padded string size also fits. It then returns the padded byte count to callers.

If an attacker supplies a string whose data bytes fit but whose required padding bytes are omitted, callers subtract and advance by more bytes than remain in the PDU. This can underflow `rawlen`, move `u8` past `ax_rbuf`, and cause subsequent parsing to read out of bounds.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched from the supplied source and reproducer evidence.

## Preconditions

- The victim parses a PDU containing attacker-controlled AgentX strings.
- A malicious AgentX peer can send a PDU with a string length that requires padding.
- The PDU includes the declared string bytes but omits some or all required padding bytes.

## Proof

`ax_recv()` passes the remaining payload length to `ax_pdutoostring()` for multiple AgentX string sites, including non-default context strings, OPEN descriptions, AgentCaps descriptions, and string varbinds.

`ax_pdutoostring()`:

- Reads the 4-byte string length.
- Subtracts only the length field from `rawlen`.
- Checks only `ostring->aos_slen > rawlen`.
- Copies exactly `aos_slen` bytes.
- Returns `4 + aos_slen`, rounded up to the next 4-byte boundary.

The reproduced case used a malicious REGISTER PDU:

- Total bytes read: 510.
- Header payload length: 490.
- Context string length: 486.
- Context string data: 486 bytes.
- Required padding: 2 bytes.
- Actual padding supplied: 0 bytes.

Because `486 <= rawlen` after the length field, `ax_pdutoostring()` accepts the string. It then returns the padded count, causing the REGISTER parser to advance `u8` to `ax_rbuf + 512`, just past the default 512-byte allocation from `ax_new()`.

The subsequent `rawlen` subtraction underflows, so the REGISTER `rawlen < 8` check is bypassed and parsing reaches:

`usr.sbin/snmpd/ax.c:245`

At that point ASan reports a `heap-buffer-overflow`, reading 0 bytes after the 512-byte `ax_rbuf` allocation.

## Why This Is A Real Bug

AgentX strings are padded to 4-byte alignment, and callers consume the padded size returned by `ax_pdutoostring()`. Therefore, validating only the unpadded string length is insufficient.

The reproducer demonstrates that a syntactically targeted malicious peer can make the parser advance past the actual PDU buffer and perform an out-of-bounds heap read during normal PDU parsing. This is a concrete denial-of-service condition and not merely a theoretical bounds issue.

## Fix Requirement

`ax_pdutoostring()` must reject strings when the required padded byte count does not fit within the remaining payload length supplied by the caller.

## Patch Rationale

The patch adds a padding-specific bounds check immediately after confirming that the declared string bytes fit:

```c
if (ostring->aos_slen % 4 != 0 && rawlen - ostring->aos_slen <
    4 - (ostring->aos_slen % 4))
	goto fail;
```

At this point `rawlen` excludes the 4-byte length field, and the prior `ostring->aos_slen > rawlen` check guarantees `rawlen - ostring->aos_slen` cannot underflow. The new condition verifies that enough remaining bytes exist for the required AgentX padding before allocation, copy, and padded `nread` return.

Malformed PDUs are rejected with `EPROTO` through the existing failure path.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/snmpd/ax.c b/usr.sbin/snmpd/ax.c
index eb9f060..1da2596 100644
--- a/usr.sbin/snmpd/ax.c
+++ b/usr.sbin/snmpd/ax.c
@@ -1410,6 +1410,9 @@ ax_pdutoostring(struct ax_pdu_header *header,
 	buf += 4;
 	if (ostring->aos_slen > rawlen)
 		goto fail;
+	if (ostring->aos_slen % 4 != 0 && rawlen - ostring->aos_slen <
+	    4 - (ostring->aos_slen % 4))
+		goto fail;
 	if ((ostring->aos_string = malloc(ostring->aos_slen + 1)) == NULL)
 		return -1;
 	memcpy(ostring->aos_string, buf, ostring->aos_slen);
```