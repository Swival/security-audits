# UDP Payload May Extend Past IP Packet

## Classification

Policy bypass, medium severity.

## Affected Locations

`dhcrelay/packet.c:293`

## Summary

`decode_udp_ip_header()` accepted UDP payload bytes that were present in the captured Ethernet frame but outside the IPv4 packet described by `ip->ip_len`. A same-link unauthenticated DHCP client could craft an IPv4 UDP frame where the IP total length was shorter than the UDP length, placing DHCP data in trailing frame bytes. The relay could then parse and forward DHCP content that was not part of the IP packet.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The relay receives a crafted Ethernet IPv4 UDP frame from a client link.
- The attacker is a same-link unauthenticated DHCP client.
- The frame contains a valid IPv4 header checksum.
- The IPv4 UDP checksum is zero, which IPv4 permits and causes checksum verification to be skipped.

## Proof

The reproduced packet used:

- A valid IPv4 header checksum.
- `udp->uh_sum = 0`.
- An IP total length shorter than the UDP length.
- DHCP bytes placed after the IPv4 packet boundary, in captured trailing frame bytes.

The vulnerable path was:

- `decode_udp_ip_header()` first verified only that the IP packet fit inside the captured frame.
- It then checked the UDP header and UDP payload against `buflen`, the full captured frame length.
- The payload bound check also used `buf + buflen`, allowing bytes after `offset + ntohs(ip->ip_len)` to be treated as UDP payload.
- `receive_packet()` copied the remaining captured frame bytes after the UDP header.
- Relay dispatch then accepted the crafted BOOTREQUEST and forwarded it to servers.

This reproduced packet smuggling across the IPv4 packet boundary.

## Why This Is A Real Bug

The IP total length field defines the end of the IPv4 packet. UDP data must be contained within that boundary. The old checks enforced that the IPv4 packet was present in the capture, but did not enforce that the UDP datagram was contained inside the IPv4 packet.

As a result, `dhcrelay` could interpret Ethernet padding or trailing capture bytes as DHCP payload. That creates a parser differential between the IPv4 packet boundary and the relay’s DHCP parser, allowing attacker-controlled data outside the IP packet to affect relay behavior.

## Fix Requirement

Validate both the UDP header and UDP payload end against:

`offset + ntohs(ip->ip_len)`

not against the full captured frame length.

## Patch Rationale

The patch changes the UDP bounds checks from capture-buffer-relative checks to IP-packet-relative checks:

- The UDP header must fit within `ntohs(ip->ip_len)`.
- The full UDP datagram length must fit within `ntohs(ip->ip_len)`.

This preserves the existing earlier check that the IP packet itself fits inside `buflen`, while preventing trailing frame bytes from being considered part of the UDP payload.

## Residual Risk

None

## Patch

```diff
diff --git a/dhcrelay/packet.c b/dhcrelay/packet.c
index fabdf1d..4d11967 100644
--- a/dhcrelay/packet.c
+++ b/dhcrelay/packet.c
@@ -272,14 +272,14 @@ decode_udp_ip_header(unsigned char *buf, size_t buflen,
 	if (buflen < offset + ntohs(ip->ip_len))
 		return (-1);
 
-	/* Assure that the UDP header is within the buffer. */
-	if (buflen < offset + ip_len + sizeof(*udp))
+	/* Assure that the UDP header is within the IP packet. */
+	if (ntohs(ip->ip_len) < ip_len + sizeof(*udp))
 		return (-1);
 	udp = (struct udphdr *)(buf + offset + ip_len);
 	udp_packets_seen++;
 
-	/* Assure that the entire UDP packet is within the buffer. */
-	if (buflen < offset + ip_len + ntohs(udp->uh_ulen))
+	/* Assure that the entire UDP packet is within the IP packet. */
+	if (ntohs(ip->ip_len) < ip_len + ntohs(udp->uh_ulen))
 		return (-1);
 	data = buf + offset + ip_len + sizeof(*udp);
```