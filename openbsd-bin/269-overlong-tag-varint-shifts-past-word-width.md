# Overlong Tag Varint Shifts Past Word Width

## Classification

Denial of service, medium severity.

## Affected Locations

`lib/libevent/event_tagging.c:129`

## Summary

`decode_tag_internal()` decodes variable-length tag IDs into a 32-bit value without bounding the varint length before shifting. A peer-controlled overlong tag can drive `shift` past the width of the promoted integer used in `(lower & 0x7f) << shift`, causing undefined behavior in the parsing path.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

An application decodes peer-controlled `evbuffer` tag data through libevent `evtag` APIs, such as:

- `evtag_decode_tag()`
- `evtag_peek()`
- `evtag_peek_length()`
- `evtag_payload_length()`
- `evtag_consume()`
- `evtag_unmarshal()`
- `evtag_unmarshal_int()`

## Proof

`decode_tag_internal()` reads each tag byte from `EVBUFFER_DATA(evbuf)` and accumulates the low seven bits:

```c
number |= (lower & 0x7f) << shift;
shift += 7;
```

For attacker-controlled bytes such as:

```text
80 80 80 80 80 80
```

the loop continues because each byte has the continuation bit set. By the sixth iteration, `shift == 35`, and the decoder executes:

```c
(lower & 0x7f) << 35
```

`lower & 0x7f` is integer-promoted before the shift, so this is a shift exponent beyond the width of a 32-bit `int`. A UBSan harness against the vulnerable source aborts deterministically with:

```text
runtime error: shift exponent 35 is too large for 32-bit type 'int'
```

## Why This Is A Real Bug

The malformed input is accepted far enough to execute undefined behavior before the decoder returns an error. The affected function is reachable from public tag decoding and unmarshalling APIs. Under the stated precondition, a remote peer can trigger the undefined shift with crafted tagged data, causing process termination in hardened or sanitizer-enabled builds and creating a denial-of-service condition.

## Fix Requirement

Reject tag varints before any shift that would exceed the valid 32-bit tag encoding range. Since tags are encoded in 7-bit groups into an `ev_uint32_t`, decoding must fail once `shift` would exceed 28 bits.

## Patch Rationale

The patch adds a guard immediately before the shift:

```c
if (shift > 28)
	return (-1);
```

This preserves valid encodings up to the fifth 7-bit group while rejecting overlong encodings before undefined behavior occurs. Returning `-1` matches the existing malformed-tag failure behavior in `decode_tag_internal()` and its callers.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/libevent/event_tagging.c b/lib/libevent/event_tagging.c
index 4716a7e..e942c96 100644
--- a/lib/libevent/event_tagging.c
+++ b/lib/libevent/event_tagging.c
@@ -128,6 +128,9 @@ decode_tag_internal(ev_uint32_t *ptag, struct evbuffer *evbuf, int dodrain)
 
 	while (count++ < len) {
 		ev_uint8_t lower = *data++;
+
+		if (shift > 28)
+			return (-1);
 		number |= (lower & 0x7f) << shift;
 		shift += 7;
```