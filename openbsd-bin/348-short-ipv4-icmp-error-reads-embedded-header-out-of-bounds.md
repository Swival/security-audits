# Short IPv4 ICMP Error Reads Embedded Header Out Of Bounds

## Classification

Out-of-bounds read; medium severity; confidence: certain.

## Affected Locations

`usr.sbin/traceroute/worker.c:505`

## Summary

`packet_ok4()` accepts short IPv4 ICMP time-exceeded and unreachable messages that contain only the minimum ICMP header, then dereferences the absent quoted IPv4 header via `hip->ip_hl`. The later length checks are performed after this dereference, so they do not prevent the out-of-bounds read.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- `traceroute` processes an attacker-sent IPv4 ICMP error.
- The ICMP type/code is accepted by `packet_ok4()`, specifically:
  - `ICMP_TIMXCEED` with `ICMP_TIMXCEED_INTRANS`
  - `ICMP_UNREACH`
- The packet has a valid outer IPv4 header and at least `ICMP_MINLEN` bytes of ICMP data, but lacks the quoted embedded IPv4 header.

## Proof

A reproduced packet with a normal 20-byte outer IPv4 header and only the 8-byte minimum ICMP header reaches the vulnerable path.

Execution flow:

- `packet_ok4()` computes the outer IPv4 header length and only requires `cc >= hlen + ICMP_MINLEN`.
- After `cc -= hlen`, `cc` is `8`.
- For accepted ICMP error types, execution reaches:
  - `hip = &icp->icmp_ip`
  - `hlen = hip->ip_hl << 2`
- With only `ICMP_MINLEN` bytes present, `hip` points immediately past the received ICMP data.
- Reading `hip->ip_hl` therefore reads beyond the received packet buffer.
- Existing checks such as `hlen + 8 <= cc` and `hlen + 12 <= cc` occur after `hip->ip_hl` has already been read.

Result: reproduced.

## Why This Is A Real Bug

The parser treats `icp->icmp_ip` as present before proving that the received ICMP payload contains a quoted IPv4 header. IPv4 ICMP error messages are attacker-controlled network input, and short ICMP errors can satisfy the current initial `ICMP_MINLEN` check. Because `hip->ip_hl` is read before validating `cc >= ICMP_MINLEN + sizeof(*hip)`, the function can read memory past the received ICMP message.

## Fix Requirement

Verify that the ICMP payload contains the quoted IPv4 header before reading any field from `icp->icmp_ip`, including `ip_hl`.

## Patch Rationale

The patch preserves direct ICMP echo-reply handling, because echo replies do not contain a quoted embedded IPv4 header. It then rejects ICMP error packets whose remaining ICMP data is shorter than `ICMP_MINLEN + sizeof(*hip)` before computing `hlen = hip->ip_hl << 2`.

This ensures `hip->ip_hl` is only read when the quoted IPv4 header is present.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/traceroute/worker.c b/usr.sbin/traceroute/worker.c
index 0865f4d..e6328c7 100644
--- a/usr.sbin/traceroute/worker.c
+++ b/usr.sbin/traceroute/worker.c
@@ -521,15 +521,17 @@ packet_ok4(struct tr_conf *conf, struct msghdr *mhdr, int cc, int *seq)
 		struct icmp *icmpp;
 
 		hip = &icp->icmp_ip;
+		if (type == ICMP_ECHOREPLY && conf->proto == IPPROTO_ICMP &&
+		    icp->icmp_id == htons(conf->ident)) {
+			*seq = ntohs(icp->icmp_seq);
+			return (-2); /* we got there */
+		}
+		if (cc < ICMP_MINLEN + sizeof(*hip))
+			return (0);
 		hlen = hip->ip_hl << 2;
 
 		switch (conf->proto) {
 		case IPPROTO_ICMP:
-			if (type == ICMP_ECHOREPLY &&
-			    icp->icmp_id == htons(conf->ident)) {
-				*seq = ntohs(icp->icmp_seq);
-				return (-2); /* we got there */
-			}
 			icmpp = (struct icmp *)((u_char *)hip + hlen);
 			if (hlen + 8 <= cc && hip->ip_p == IPPROTO_ICMP &&
 			    icmpp->icmp_id == htons(conf->ident)) {
```