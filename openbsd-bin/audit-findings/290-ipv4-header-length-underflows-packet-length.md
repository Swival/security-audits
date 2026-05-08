# IPv4 header length underflows packet length

## Classification

- Type: out-of-bounds read
- Severity: high
- Confidence: certain

## Affected Locations

- `usr.sbin/eigrpd/packet.c:560`
- `usr.sbin/eigrpd/packet.c:565`
- `usr.sbin/eigrpd/packet.c:626`
- `usr.sbin/eigrpd/in_cksum.c:57`

## Summary

`recv_packet` accepts an IPv4 raw packet whose declared IPv4 header length exceeds the received packet length. It then advances the packet buffer by `ip_hdr.ip_hl << 2` and subtracts that value from a `uint16_t len`, causing integer underflow. The wrapped length is later passed to `in_cksum`, which reads beyond the received packet buffer and can terminate `eigrpd`.

## Provenance

- Source: Swival Security Scanner
- URL: https://swival.dev
- Status: reproduced and patched

## Preconditions

- Attacker is a remote EIGRP-speaking IPv4 host.
- Packet passes interface lookup, source subnet validation, and destination address validation.
- Packet has `ntohs(ip_hdr.ip_len) == len`.
- Packet has `ip_hdr.ip_hl << 2` larger than the received packet length.

## Proof

`recv_packet` verifies only that the received IPv4 packet is at least the size of `struct ip` and that the IPv4 `ip_len` field equals the received length:

```c
if (len < sizeof(ip_hdr)) {
	log_debug("%s: bad packet size", __func__);
	return;
}
memcpy(&ip_hdr, buf, sizeof(ip_hdr));
if (ntohs(ip_hdr.ip_len) != len) {
	log_debug("%s: invalid IP packet length %u", __func__,
	    ntohs(ip_hdr.ip_len));
	return;
}
buf += ip_hdr.ip_hl << 2;
len -= ip_hdr.ip_hl << 2;
```

A packet with `len = 20`, `ip_len = 20`, and `ip_hl = 15` passes those checks. The code then advances `buf` by `60` bytes and subtracts `60` from a `uint16_t len`, wrapping `len` from `20` to `65496`.

That wrapped length bypasses the later EIGRP minimum-size check and reaches:

```c
if (in_cksum(eigrp_hdr, len)) {
```

`in_cksum` accepts the wrapped value because it only rejects lengths `>= 65536`, so it performs an out-of-bounds checksum read from memory beyond the received packet.

## Why This Is A Real Bug

The IPv4 IHL field is attacker-controlled input from the raw packet. The code trusts it without checking that the header byte length is contained within the received IPv4 packet. Because `len` is `uint16_t`, subtracting an excessive header length wraps instead of failing. The resulting large length is used as a trusted buffer length for checksum calculation, producing an out-of-bounds read before EIGRP packet parsing can reject the malformed input.

## Fix Requirement

Reject IPv4 packets when the IPv4 header length in bytes exceeds the received packet length before advancing `buf` or subtracting from `len`.

## Patch Rationale

The patch adds a bounds check immediately after validating `ip_len` and before using `ip_hdr.ip_hl << 2` to adjust the packet buffer and length. This prevents `buf` from being moved outside the received packet and prevents `len` from underflowing.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/eigrpd/packet.c b/usr.sbin/eigrpd/packet.c
index dcf97cb..a3d6a9e 100644
--- a/usr.sbin/eigrpd/packet.c
+++ b/usr.sbin/eigrpd/packet.c
@@ -562,6 +562,10 @@ recv_packet(int fd, short event, void *bula)
 			    ntohs(ip_hdr.ip_len));
 			return;
 		}
+		if ((ip_hdr.ip_hl << 2) > len) {
+			log_debug("%s: bad packet size", __func__);
+			return;
+		}
 		buf += ip_hdr.ip_hl << 2;
 		len -= ip_hdr.ip_hl << 2;
 		dest.v4 = ip_hdr.ip_dst;
```