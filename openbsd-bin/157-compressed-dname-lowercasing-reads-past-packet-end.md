# compressed dname lowercasing reads past packet end

## Classification

Out-of-bounds read, medium severity, remotely triggerable by a crafted DNS packet under the stated call path.

## Affected Locations

`sbin/unwind/libunbound/util/data/dname.c:159`

## Summary

`pkt_dname_tolower` validates that the first dname byte is inside the packet, then reads a label byte. When that byte is a DNS compression pointer marker, the function immediately evaluates the pointer offset using `*dname` as the second pointer byte. If the pointer marker is the final byte of the packet, `dname` already equals `sldns_buffer_end(pkt)`, so this dereference reads one byte past the packet buffer.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- A caller invokes `pkt_dname_tolower` on an attacker-controlled packet dname.
- The packet dname begins at an in-bounds byte.
- The first dname byte is a compression-pointer first byte, such as `0xc0`.
- That compression-pointer first byte is also the final byte of the DNS packet.

## Proof

The vulnerable function performs only an initial start-pointer bound check:

```c
if(dname >= sldns_buffer_end(pkt))
	return;
lablen = *dname++;
```

If `lablen` is a compression pointer first byte and it was read from the packet’s final byte, `dname` now points exactly to `sldns_buffer_end(pkt)`. The compression-pointer branch then dereferences `*dname` before checking that the second pointer byte exists:

```c
if(LABEL_IS_PTR(lablen)) {
	if((size_t)PTR_OFFSET(lablen, *dname) 
		>= sldns_buffer_limit(pkt))
		return;
```

A reproduced path exists when `use-caps-for-id` is enabled: `serviced_callbacks` calls `pkt_dname_tolower(c->buffer, sldns_buffer_at(c->buffer, 12))` on the caps-failure cleanup path at `sbin/unwind/libunbound/services/outside_network.c:3044`.

A 13-byte response with `QDCOUNT > 0`, acceptable `rcode`, matching UDP ID/address, and byte 12 set to `0xc0` places the compression-pointer first byte at the final packet byte. `serviced_check_qname` rejects the malformed qname, and that rejection leads to the cleanup call.

An ASan harness using the committed `pkt_dname_tolower` confirmed `READ of size 1` at `dname.c:160` for a 13-byte `sldns_buffer` ending in `0xc0`.

## Why This Is A Real Bug

DNS compression pointers require two bytes. The function recognizes the first byte as a pointer but does not prove the second byte is within the packet before dereferencing it. The existing offset validation is too late because computing `PTR_OFFSET(lablen, *dname)` already performs the out-of-bounds read.

The bug is reachable from remote DNS input in the reproduced configuration, and the malformed qname rejection path still calls `pkt_dname_tolower`, so parser rejection does not prevent the invalid read.

## Fix Requirement

Before reading the second byte of a compression pointer, require:

```c
dname < sldns_buffer_end(pkt)
```

If the second byte is absent, return without dereferencing it.

## Patch Rationale

The patch adds an explicit end-of-packet check in the compression-pointer branch before any use of `*dname`:

```diff
@@ -157,6 +157,8 @@ pkt_dname_tolower(sldns_buffer* pkt, uint8_t* dname)
 	lablen = *dname++;
 	while(lablen) {
 		if(LABEL_IS_PTR(lablen)) {
+			if(dname >= sldns_buffer_end(pkt))
+				return;
 			if((size_t)PTR_OFFSET(lablen, *dname) 
 				>= sldns_buffer_limit(pkt))
 				return;
```

This preserves existing behavior for valid two-byte pointers and malformed in-bounds pointers, while rejecting the truncated pointer case before the out-of-bounds dereference.

## Residual Risk

None

## Patch

`157-compressed-dname-lowercasing-reads-past-packet-end.patch`

```diff
diff --git a/sbin/unwind/libunbound/util/data/dname.c b/sbin/unwind/libunbound/util/data/dname.c
index 5370aa6..787e6d3 100644
--- a/sbin/unwind/libunbound/util/data/dname.c
+++ b/sbin/unwind/libunbound/util/data/dname.c
@@ -157,6 +157,8 @@ pkt_dname_tolower(sldns_buffer* pkt, uint8_t* dname)
 	lablen = *dname++;
 	while(lablen) {
 		if(LABEL_IS_PTR(lablen)) {
+			if(dname >= sldns_buffer_end(pkt))
+				return;
 			if((size_t)PTR_OFFSET(lablen, *dname) 
 				>= sldns_buffer_limit(pkt))
 				return;
```