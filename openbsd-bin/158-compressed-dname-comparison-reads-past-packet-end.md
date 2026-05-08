# Compressed dname comparison reads past packet end

## Classification

Out-of-bounds read, medium severity.

## Affected Locations

`sbin/unwind/libunbound/util/data/dname.c:240`

## Summary

`dname_pkt_compare()` handles DNS compression pointers by reading the second pointer byte before proving that byte is still inside the packet buffer. A crafted DNS packet can place a pointer marker byte such as `0xc0` at the final byte of the packet, causing a one-byte read past the DNS packet allocation during compressed domain-name comparison.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- A crafted DNS packet reaches `dname_pkt_compare()`.
- One compared dname begins with a compression pointer marker at the final byte of the packet.
- The second compression-pointer byte is absent from the packet buffer.

## Proof

`dname_pkt_compare()` initializes label bytes with:

```c
len1 = *d1++;
len2 = *d2++;
```

When `len1` is a compression pointer marker, the function immediately evaluates:

```c
PTR_OFFSET(len1, *d1)
```

before checking whether `d1` is within the packet limit. If the attacker-controlled dname starts at the final packet byte and that byte is `0xc0`, then `*d1` reads one byte beyond the DNS packet buffer.

The later check against `sldns_buffer_limit(pkt)` validates only the computed pointer offset and occurs after the out-of-bounds dereference.

A practical path exists through the auth-zone SOA probe handler: `check_packet_ok()` checks only that at least one byte remains, then calls `dname_pkt_compare()` on the answer owner name before validating it with `pkt_dname_len()` at `sbin/unwind/libunbound/services/authzone.c:4347`.

A malicious SOA-probe peer can send a reply with valid header and query fields, `ANCOUNT=1`, and a single final answer-name byte `0xc0`. The UDP receive path sets the buffer limit to the datagram length, so that byte is the packet end.

An ASan harness against the committed `dname.c` confirmed a `heap-buffer-overflow` at `dname.c:243`, reading exactly one byte past the backing packet allocation.

## Why This Is A Real Bug

DNS compression pointers are two-byte fields. The code recognizes the first pointer byte but dereferences the second byte without first checking that it exists. Packet-level validation is not guaranteed before this comparison path, and the reproduced SOA probe path reaches the vulnerable function with only a one-byte remaining check. Therefore malformed remote DNS input can trigger memory access outside the received packet allocation.

## Fix Requirement

Before evaluating `PTR_OFFSET(len, *d)` for either compared dname, verify that the second pointer byte pointer is still inside the packet buffer.

## Patch Rationale

The patch adds explicit bounds checks before dereferencing the second compression-pointer byte:

```c
if(d1 >= sldns_buffer_end(pkt))
	return -1;
```

and:

```c
if(d2 >= sldns_buffer_end(pkt))
	return 1;
```

These checks preserve the existing comparison failure direction for malformed `d1` and `d2` inputs while preventing `*d1` or `*d2` from being evaluated when the pointer byte would be read past the packet end.

## Residual Risk

None

## Patch

```diff
diff --git a/sbin/unwind/libunbound/util/data/dname.c b/sbin/unwind/libunbound/util/data/dname.c
index 5370aa6..c5c19e1 100644
--- a/sbin/unwind/libunbound/util/data/dname.c
+++ b/sbin/unwind/libunbound/util/data/dname.c
@@ -240,6 +240,8 @@ dname_pkt_compare(sldns_buffer* pkt, uint8_t* d1, uint8_t* d2)
 	while( len1 != 0 || len2 != 0 ) {
 		/* resolve ptrs */
 		if(LABEL_IS_PTR(len1)) {
+			if(d1 >= sldns_buffer_end(pkt))
+				return -1;
 			if((size_t)PTR_OFFSET(len1, *d1)
 				>= sldns_buffer_limit(pkt))
 				return -1;
@@ -250,6 +252,8 @@ dname_pkt_compare(sldns_buffer* pkt, uint8_t* d1, uint8_t* d2)
 			continue;
 		}
 		if(LABEL_IS_PTR(len2)) {
+			if(d2 >= sldns_buffer_end(pkt))
+				return 1;
 			if((size_t)PTR_OFFSET(len2, *d2)
 				>= sldns_buffer_limit(pkt))
 				return 1;
```