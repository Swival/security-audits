# Jumbo Packets Bypass RH0 Rejection

## Classification

security_control_failure, high severity, confidence certain

## Affected Locations

`netinet6/ip6_input.c:777`

## Summary

IPv6 jumbograms with `ip6_plen == 0` can bypass the early RH0 rejection scan in `ip6_check_rh0hdr()`. The scan bounds `lim` are derived from the IPv6 payload length field before Hop-by-Hop Jumbo Payload processing occurs. For jumbo packets, that field is zero, so the RH0 scan only considers the fixed IPv6 header and fails open before reaching the Routing Header.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- IPv6 forwarding is enabled.
- The ingress link accepts IPv6 jumbo packets.
- A remote IPv6 sender can transmit a packet with Hop-by-Hop options followed by an RH0 Routing Header.

## Proof

The reproduced packet path is deterministic:

- `ip6_check_rh0hdr()` runs before `ip6_hbhchcheck()` parses Hop-by-Hop Jumbo Payload options.
- For a jumbo packet, `ip6->ip6_plen == 0`, so the original `lim` becomes only `sizeof(struct ip6_hdr)`.
- With `ip6_nxt == IPPROTO_HOPOPTS`, `off == 40`; therefore `off + sizeof(opt6) > lim` is true.
- `ip6_check_rh0hdr()` returns `0`, meaning accept, without scanning the following Routing Header.
- Later, `ip6_hopopts_input()` accepts the valid `IP6OPT_JUMBO` option and sets `plen` from the jumbo length.
- The forwarding path does not re-run RH0 rejection before `ip6_forward()`.

Relevant reproduced locations:

- `netinet6/ip6_input.c:764`: fail-open return from `ip6_check_rh0hdr()`.
- `netinet6/ip6_input.c:655`: later Hop-by-Hop processing.
- `netinet6/ip6_input.c:881`: `IP6OPT_JUMBO` accepted.
- `netinet6/ip6_input.c:944`: jumbo payload length assigned.
- `netinet6/ip6_input.c:621`: packet forwarded after Hop-by-Hop processing.
- `netinet6/ip6_forward.c:326`: forwarded via `if_output_tso()` when routing and MTU allow.

## Why This Is A Real Bug

The code explicitly intends to reject RH0 more strictly than RFC5095 by scanning the extension-header chain before forwarding. Jumbo packets make that control fail open because the scan uses the unprocessed 16-bit IPv6 payload length field as the upper bound. Since a valid jumbogram must encode payload length through the Hop-by-Hop Jumbo Payload option and leave `ip6_plen` as zero, the control rejects ordinary RH0 packets but misses the jumbo variant.

A remote sender can therefore cause an IPv6-forwarding router that accepts jumbograms to forward a packet containing RH0, contrary to the implemented security policy.

## Fix Requirement

`ip6_check_rh0hdr()` must not bound its extension-header scan to `sizeof(struct ip6_hdr)` when `ip6_plen == 0`. It must either parse the jumbo payload length before scanning for RH0 or use the mbuf packet length as the scan bound for jumbo packets.

## Patch Rationale

The patch treats `ip6_plen == 0` as the jumbo-payload case and sets `lim` to `m->m_pkthdr.len`. This allows `ip6_check_rh0hdr()` to inspect the Hop-by-Hop header and continue to the following Routing Header, where RH0 is detected and rejected.

For non-jumbo packets, the existing behavior is preserved by continuing to cap the scan at:

`min(m->m_pkthdr.len, ntohs(ip6->ip6_plen) + sizeof(*ip6))`

This narrowly fixes the fail-open condition without changing normal packet length handling.

## Residual Risk

None

## Patch

```diff
diff --git a/netinet6/ip6_input.c b/netinet6/ip6_input.c
index e6d5126..81aba6d 100644
--- a/netinet6/ip6_input.c
+++ b/netinet6/ip6_input.c
@@ -730,7 +730,8 @@ ip6_check_rh0hdr(struct mbuf *m, int *offp)
 	int done = 0, lim, off, rh_cnt = 0;
 
 	off = ((caddr_t)ip6 - m->m_data) + sizeof(struct ip6_hdr);
-	lim = min(m->m_pkthdr.len, ntohs(ip6->ip6_plen) + sizeof(*ip6));
+	lim = ntohs(ip6->ip6_plen) == 0 ? m->m_pkthdr.len :
+	    min(m->m_pkthdr.len, ntohs(ip6->ip6_plen) + sizeof(*ip6));
 	do {
 		switch (proto) {
 		case IPPROTO_ROUTING:
```