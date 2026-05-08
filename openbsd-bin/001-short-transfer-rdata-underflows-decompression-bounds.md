# Short Transfer RDATA Underflows Decompression Bounds

## Classification

High severity out-of-bounds read.

Confidence: certain.

## Affected Locations

`sbin/unwind/libunbound/services/authzone.c:984`

`sbin/unwind/libunbound/services/authzone.c:1378`

`sbin/unwind/libunbound/services/authzone.c:1393`

## Summary

A malicious configured AXFR/IXFR master can send a syntactically accepted transfer packet containing compressed RR RDATA shorter than the fixed-size fields implied by the RR type descriptor. During zone update processing, `decompress_rr_into_buffer()` copies fixed RDATA fields before proving that the declared remaining RDATA length is large enough, allowing reads past the copied transfer packet buffer.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was independently reproduced with a minimal ASan harness against the committed decompression logic.

## Preconditions

Zone transfers are configured from an attacker-controlled master.

## Proof

`auth_xfer_transfer_tcp_callback()` accepts master packets after `check_xfer_packet()` validates only packet-level structure and that `sldns_buffer_remaining(pkt) >= rdlen`.

Accepted packets are copied by `xfer_link_data()` and later processed by `apply_ixfr()` or `apply_axfr()`, which pass each RR to `az_insert_rr_decompress()`.

`az_insert_rr_decompress()` calls `decompress_rr_into_buffer()`. For typed RDATA with dnames, the decompressor iterates `desc->_wireformat`. For fixed-width fields, it computes `len = get_rdf_size(desc->_wireformat[rdf])` and then writes `len` bytes from `rd` before the old code proved `rdlen >= len`.

MX RDATA is a fixed `INT16` preference followed by a dname. An MX RR with `RDLENGTH=1` reaches the fixed-field path and reads one byte past the declared RDATA. If the RR is the last RR in its transfer packet, the read crosses the copied packet chunk boundary.

The ASan reproducer confirmed a heap-buffer-overflow read in `sldns_buffer_write_at` using a valid transfer-shaped packet containing short MX RDATA.

## Why This Is A Real Bug

The transfer packet parser only verifies that the packet contains the declared RDATA length. It does not verify that typed RDATA is long enough for the descriptor-driven decompressor.

`decompress_rr_into_buffer()` then interprets the short RDATA according to the RR type descriptor and copies fixed-width fields from `rd` without first checking that enough bytes remain in the RR’s declared RDATA. This creates an out-of-bounds read from attacker-controlled transfer input during normal AXFR/IXFR processing.

## Fix Requirement

Before every fixed-field RDATA copy, reject the RR if `rdlen < len`.

Before subtracting compressed dname length from `rdlen`, reject if `rdlen < compressed_len`.

## Patch Rationale

The patch adds explicit bounds checks at the two points where `rdlen` is decremented by a computed component length:

- After computing `compressed_len`, the code now rejects if the compressed dname consumed more bytes than remain in the RR’s declared RDATA.
- Before copying a fixed-width or string field, the code now rejects if the remaining declared RDATA is shorter than the requested copy length.

This preserves existing decompression behavior for valid records while converting malformed short RDATA into a parse failure before any out-of-bounds read or unsigned underflow can occur.

## Residual Risk

None

## Patch

```diff
diff --git a/sbin/unwind/libunbound/services/authzone.c b/sbin/unwind/libunbound/services/authzone.c
index 60ccc86..ade60e1 100644
--- a/sbin/unwind/libunbound/services/authzone.c
+++ b/sbin/unwind/libunbound/services/authzone.c
@@ -1378,6 +1378,8 @@ decompress_rr_into_buffer(struct sldns_buffer* buf, uint8_t* pkt,
 				sldns_buffer_skip(buf, (ssize_t)uncompressed_len);
 				compressed_len = sldns_buffer_position(
 					&pktbuf) - oldpos;
+				if(rdlen < compressed_len)
+					return 0;
 				rd += compressed_len;
 				rdlen -= compressed_len;
 				count--;
@@ -1391,6 +1393,8 @@ decompress_rr_into_buffer(struct sldns_buffer* buf, uint8_t* pkt,
 				break;
 			}
 			if(len) {
+				if(rdlen < len)
+					return 0;
 				if(!sldns_buffer_available(buf, len))
 					return 0; /* too long for buffer */
 				sldns_buffer_write(buf, rd, len);
```