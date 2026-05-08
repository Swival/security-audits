# Missing String Padding Validation Underflows PDU Parser Length

## Classification

High severity out-of-bounds read.

Confidence: certain.

## Affected Locations

- `lib/libagentx/ax.c:200`
- `lib/libagentx/ax.c:1289`
- `lib/libagentx/ax.c:1296`

## Summary

`ax_pdutoostring()` validates only the declared string length against the remaining PDU payload, but returns a padded 4-byte-aligned consumption length. If the payload contains the string bytes but omits required padding bytes, the returned length can exceed the available bytes. `ax_recv()` then subtracts that oversized value from a `size_t rawlen`, underflowing the parser length and allowing subsequent PDU parsing to read beyond the received buffer.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was independently reproduced with a crafted AgentX PDU and confirmed under AddressSanitizer.

## Preconditions

- The victim accepts AgentX PDUs from a peer.
- The peer can send a PDU with `AX_PDU_FLAG_NON_DEFAULT_CONTEXT`.
- The context string length is not 4-byte aligned.
- The payload omits one or more required string padding bytes.
- The PDU type continues parsing structured payload data after the context, such as `GET`, `GETNEXT`, or `GETBULK`.

## Proof

A malicious AgentX peer sends a `GET` PDU with a non-default context string whose declared string length is accepted, but whose padded length exceeds the payload.

Observed parser behavior:

- `ax_recv()` reads exactly `header.aph_plength` bytes.
- `ax_recv()` calls `ax_pdutoostring()` for the non-default context.
- `ax_pdutoostring()` checks only `aos_slen <= rawlen` after the 4-byte length field.
- A crafted string length of `487` with only `487` bytes remaining passes validation.
- `ax_pdutoostring()` returns the padded consumption length `492`.
- `ax_recv()` subtracts `492` from a smaller `size_t rawlen`, underflowing it.
- `ax_recv()` advances `u8` beyond the received buffer.
- Because the PDU type is `GET`, the search-range loop runs while `rawlen > 0`.
- `ax_recv()` calls `ax_pdutooid()`, which immediately reads `*buf++` beyond the heap buffer.

ASan confirmed the out-of-bounds read:

```text
ERROR: AddressSanitizer: heap-buffer-overflow
READ of size 1
#0 ax_pdutooid ax.c:1250
#1 ax_recv ax.c:231
```

## Why This Is A Real Bug

The AgentX string encoding includes padding to a 4-byte boundary. The parser must verify that both the string bytes and required padding bytes are present before reporting how many bytes were consumed.

The vulnerable function validates only the unpadded string length:

```c
if (ostring->aos_slen > rawlen)
	goto fail;
```

It then returns the padded length:

```c
nread = 4 + ostring->aos_slen;
if (ostring->aos_slen % 4 != 0)
	nread += 4 - (ostring->aos_slen % 4);
```

This mismatch lets a malformed but length-consistent payload make `nread` larger than the available payload. Since `ax_recv()` stores the remaining length in `size_t`, subtracting the oversized `nread` underflows instead of becoming negative. The following parser loop treats the underflowed length as valid and reads past the received PDU.

## Fix Requirement

Reject AgentX strings when the padded string length exceeds the available raw payload length.

The validation must occur before `ax_pdutoostring()` returns `nread`, so callers never receive a consumption length larger than the provided `rawlen`.

## Patch Rationale

The patch adds a direct padded-length bounds check immediately after validating the declared string length:

```c
if (ostring->aos_slen + (4 - (ostring->aos_slen % 4)) % 4 > rawlen)
	goto fail;
```

This computes the exact number of bytes required after the 4-byte string length field: the string length plus zero to three padding bytes. If those bytes are not present in the remaining payload, the string is rejected with `EPROTO`.

This prevents `ax_pdutoostring()` from returning a padded consumption length that exceeds the caller-provided `rawlen`, eliminating the downstream `size_t` underflow in `ax_recv()`.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/libagentx/ax.c b/lib/libagentx/ax.c
index f4d6eb7..1ac9e7b 100644
--- a/lib/libagentx/ax.c
+++ b/lib/libagentx/ax.c
@@ -1288,6 +1288,8 @@ ax_pdutoostring(struct ax_pdu_header *header,
 	buf += 4;
 	if (ostring->aos_slen > rawlen)
 		goto fail;
+	if (ostring->aos_slen + (4 - (ostring->aos_slen % 4)) % 4 > rawlen)
+		goto fail;
 	if ((ostring->aos_string = malloc(ostring->aos_slen + 1)) == NULL)
 		return -1;
 	memcpy(ostring->aos_string, buf, ostring->aos_slen);
```