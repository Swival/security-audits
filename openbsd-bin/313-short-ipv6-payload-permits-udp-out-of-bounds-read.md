# Short IPv6 Payload Permits UDP Out-Of-Bounds Read

## Classification

High severity out-of-bounds read in IPv6 UDP packet decoding.

Confidence: certain.

## Affected Locations

`usr.sbin/dhcrelay6/packet.c:207`

## Summary

`decode_udp_ip6_header()` accepts IPv6 packets whose `ip6_nxt` is UDP but whose IPv6 payload length is shorter than a UDP header. It then reads `uh_sport`, `uh_dport`, and, when checksum offload is not trusted, computes a checksum using an underflowed payload length. A remote IPv6 sender on a segment monitored by `dhcrelay6` can trigger an out-of-bounds read and likely daemon crash.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was independently reproduced with an ASan harness using the committed decode logic.

## Preconditions

- `dhcrelay6` processes attacker-supplied IPv6 Ethernet frames.
- The attacker can send a crafted IPv6 frame to a layer-2 segment monitored by `dhcrelay6 -l`.
- Trusted UDP checksum offload is not available, or `M_UDP_CSUM_IN_OK` is not set.
- The crafted frame passes the fixed-offset BPF port check.

## Proof

`receive_packet()` passes the captured frame length after Ethernet to `decode_udp_ip6_header()` at `usr.sbin/dhcrelay6/bpf.c:383`.

Inside `decode_udp_ip6_header()`:

- The function checks only that the captured buffer contains an IPv6 header.
- It reads `ptotal = ntohs(ip6->ip6_plen)`.
- It rejects only when `ptotal > plen`.
- It accepts `ip6_nxt == IPPROTO_UDP`.
- Before the patch, it immediately treated bytes after the IPv6 header as `struct udphdr`.

A crafted IPv6 packet with:

- `ip6_nxt = IPPROTO_UDP`
- `ip6_plen = 0`
- UDP checksum flags clear

reaches the UDP decode path even though the declared IPv6 payload is shorter than `sizeof(struct udphdr)`.

Before the patch, the code then reads beyond the received packet payload:

```c
uh = (struct udphdr *)((uint8_t *)ip6 + sizeof(*ip6));
ss2sin6(&pc->pc_src)->sin6_port = uh->uh_sport;
ss2sin6(&pc->pc_dst)->sin6_port = uh->uh_dport;
```

If checksum validation runs, `ptotal - sizeof(*uh)` underflows because `ptotal < sizeof(*uh)`, causing `checksum()` to read far beyond the captured packet buffer.

The reproducer confirmed this condition with ASan: an IPv6 frame with `ip6_nxt=UDP`, `ip6_plen=0`, and checksum flags clear crashes with a heap-buffer-overflow in `checksum()`.

## Why This Is A Real Bug

The code assumes that `ip6_nxt == IPPROTO_UDP` implies that the IPv6 payload contains a complete UDP header. That assumption is false. IPv6 `ip6_plen` is attacker-controlled packet data, and a packet may declare a UDP next header while providing fewer than eight UDP header bytes.

The existing bounds checks do not prevent this:

- `plen < sizeof(*ip6)` only verifies the IPv6 header is captured.
- `ptotal > plen` only verifies the declared IPv6 payload is not larger than the supplied length.
- No check requires `ptotal >= sizeof(struct udphdr)` before UDP header fields are read.

This permits out-of-bounds reads past the received packet buffer and can crash the daemon.

## Fix Requirement

Reject packets with `ip6_plen < sizeof(struct udphdr)` before reading any UDP header field or using the UDP header in checksum validation.

## Patch Rationale

The patch adds the missing minimum UDP payload-length check after confirming that the IPv6 next header is UDP and before assigning `uh` or reading `uh_sport` / `uh_dport`.

```diff
+	if (ptotal < sizeof(*uh)) {
+		log_debug("UDP packet too small (%ld)", ptotal);
+		return -1;
+	}
```

This prevents:

- Direct reads of UDP source and destination ports from an incomplete UDP header.
- Checksum validation over an underflowed payload length.
- Out-of-bounds reads past the captured packet buffer for short IPv6 UDP payloads.

## Residual Risk

None

## Patch

`313-short-ipv6-payload-permits-udp-out-of-bounds-read.patch`

```diff
diff --git a/usr.sbin/dhcrelay6/packet.c b/usr.sbin/dhcrelay6/packet.c
index f87fa46..159c11e 100644
--- a/usr.sbin/dhcrelay6/packet.c
+++ b/usr.sbin/dhcrelay6/packet.c
@@ -204,6 +204,10 @@ decode_udp_ip6_header(unsigned char *p, int off, struct packet_ctx *pc,
 		log_debug("expected UDP header, got %#02X", ip6->ip6_nxt);
 		return -1;
 	}
+	if (ptotal < sizeof(*uh)) {
+		log_debug("UDP packet too small (%ld)", ptotal);
+		return -1;
+	}
 
 	uh = (struct udphdr *)((uint8_t *)ip6 + sizeof(*ip6));
 	ss2sin6(&pc->pc_src)->sin6_port = uh->uh_sport;
```