# KEY RR length unchecked before header reads

## Classification

Out-of-bounds read.

Severity: medium.

Confidence: certain.

## Affected Locations

`sbin/isakmpd/dnssec.c:192`

## Summary

`dns_get_key()` parses DNSSEC-validated DNS `KEY` RDATA as though every record contains the four-byte KEY header. It reads header bytes at offsets 0, 2, and 3 before checking `rdi_length`. A DNSSEC-validated `KEY` RR shorter than four bytes can therefore cause an out-of-bounds read during peer key lookup.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced by tracing the peer-ID-derived DNS `T_KEY` lookup, DNSSEC validation gate, and subsequent unchecked RDATA header reads.

## Preconditions

- DNSSEC validation is enabled for the peer key lookup path.
- A malicious IKE peer can select an ID that resolves to an attacker-controlled DNSSEC-signed `KEY` RR.
- The validated `KEY` RR has `rdi_length < 4`.

## Proof

`dns_get_key()` derives a DNS name from the peer ID and queries `T_KEY`:

- `sbin/isakmpd/dnssec.c:162` calls `getrrsetbyname(name, C_IN, T_KEY, 0, &rr)`.
- `sbin/isakmpd/dnssec.c:175` rejects only responses lacking `RRSET_VALIDATED`.
- The RR loop then treats each RDATA buffer as a DNS KEY header.
- `sbin/isakmpd/dnssec.c:195` reads byte 0 for `flags`.
- `sbin/isakmpd/dnssec.c:196` reads byte 2 for `protocol`.
- `sbin/isakmpd/dnssec.c:197` reads byte 3 for `algorithm`.
- The first length-derived validation occurs later at `sbin/isakmpd/dnssec.c:209`, after those reads.

A validated `KEY` RR with `rdi_length = 3` deterministically reads one byte past the RDATA buffer for `algorithm`. Lengths 0, 1, and 2 read out of bounds earlier.

DNSSEC validation does not rule out this malformed shape. The reproduced analysis found no embedded-name canonicalization constraint for `KEY` in `sbin/unwind/libunbound/sldns/rrdef.c:295`, and packet parsing accepts packet-bounded RDLENGTH for such records through `sbin/unwind/libunbound/util/data/msgparse.c:645`, `sbin/unwind/libunbound/util/data/msgparse.c:649`, and `sbin/unwind/libunbound/util/data/msgparse.c:690`.

## Why This Is A Real Bug

The code trusts DNSSEC validation as authenticity, not structural sufficiency. Authentic malformed RDATA can still be shorter than the parser’s required fixed header size. Since `dns_get_key()` dereferences offsets up to 3 before proving `rdi_length >= 4`, attacker-controlled validated data can drive an out-of-bounds read before peer signature validation completes.

## Fix Requirement

Require `rr->rri_rdatas[i].rdi_length >= 4` before reading any DNS KEY header field from `rdi_data`.

## Patch Rationale

The patch adds a length guard at the start of the per-RDATA loop:

```c
if (rr->rri_rdatas[i].rdi_length < 4)
	continue;
```

This ensures all subsequent fixed-header reads at offsets 0, 2, and 3 are within the advertised RDATA bounds. Short malformed records are ignored, matching the existing behavior for records that fail later key validation.

## Residual Risk

None

## Patch

```diff
diff --git a/sbin/isakmpd/dnssec.c b/sbin/isakmpd/dnssec.c
index d4857d3..8871b1f 100644
--- a/sbin/isakmpd/dnssec.c
+++ b/sbin/isakmpd/dnssec.c
@@ -192,6 +192,9 @@ dns_get_key(int type, struct message *msg, int *keylen)
 	 * first.
 	 */
 	for (i = 0; i < rr->rri_nrdatas && key_rr.datalen == 0; i++) {
+		if (rr->rri_rdatas[i].rdi_length < 4)
+			continue;
+
 		key_rr.flags = ntohs((u_int16_t) * rr->rri_rdatas[i].rdi_data);
 		key_rr.protocol = *(rr->rri_rdatas[i].rdi_data + 2);
 		key_rr.algorithm = *(rr->rri_rdatas[i].rdi_data + 3);
```