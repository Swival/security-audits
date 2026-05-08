# Verbose IPv6 Packet Dump Overreads Reply Buffer

## Classification

Medium severity out-of-bounds read.

## Affected Locations

`usr.sbin/traceroute/worker.c:654`

## Summary

In verbose IPv6 traceroute, `packet_ok6()` hex-dumps nonmatching ICMPv6 replies. The dump pointer is advanced past the ICMPv6 header, but the loop still prints `cc` bytes, where `cc` is the full received ICMPv6 packet length. This reads `sizeof(struct icmp6_hdr)` bytes past the received packet buffer and can disclose adjacent process memory to traceroute output.

## Provenance

Verified from supplied source, reproduced finding, and patch data.

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

IPv6 traceroute runs with verbose output enabled.

## Proof

`packet_ok6()` receives attacker-controlled ICMPv6 data through `mhdr->msg_iov[0].iov_base` and the received length `cc`.

It rejects only packets shorter than `sizeof(struct icmp6_hdr)`. For a valid but nonmatching ICMPv6 reply, execution reaches the verbose dump.

In the verbose block:

```c
p = (u_int8_t *)(icp + 1);
for (i = 0; i < cc; i++) {
	printf("%02x", p[i]);
}
```

`p` points after the ICMPv6 header, but `cc` still describes the full packet starting at `icp`. Therefore only `cc - sizeof(*icp)` bytes are valid from `p`.

For a 512-byte received ICMPv6 packet, the loop prints 512 bytes starting at `packet + 8`, reading through `packet[519]` and overreading 8 bytes beyond the 512-byte receive buffer.

## Why This Is A Real Bug

The read length and read base are inconsistent:

- `cc` is the full length of the received ICMPv6 data.
- `icp` points to the start of that received data.
- `p = icp + 1` skips the ICMPv6 header.
- The loop still reads `cc` bytes from `p`.

A malicious IPv6 host can send a valid nonmatching ICMPv6 reply while the victim runs verbose IPv6 traceroute. The process then prints bytes past the receive buffer in the verbose packet dump.

## Fix Requirement

The verbose dump must read only bytes that remain after the ICMPv6 header, or it must keep the dump pointer at the ICMPv6 header when printing `cc` bytes.

## Patch Rationale

The patch keeps the existing dump semantics of printing data after the ICMPv6 header and adjusts the loop bound to match that pointer:

```c
for (i = 0; i < cc - sizeof(*icp); i++)
```

It also updates the trailing newline condition to use the same adjusted dump length:

```c
if ((cc - sizeof(*icp)) % WIDTH != 0)
```

Because `packet_ok6()` already returns early when `cc < sizeof(struct icmp6_hdr)`, the subtraction is safe at this point.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/traceroute/worker.c b/usr.sbin/traceroute/worker.c
index 0865f4d..1ee5c84 100644
--- a/usr.sbin/traceroute/worker.c
+++ b/usr.sbin/traceroute/worker.c
@@ -657,7 +657,7 @@ packet_ok6(struct tr_conf *conf, struct msghdr *mhdr, int cc, int *seq)
 		    icp->icmp6_code);
 		p = (u_int8_t *)(icp + 1);
 #define WIDTH	16
-		for (i = 0; i < cc; i++) {
+		for (i = 0; i < cc - sizeof(*icp); i++) {
 			if (i % WIDTH == 0)
 				printf("%04x:", i);
 			if (i % 4 == 0)
@@ -666,7 +666,7 @@ packet_ok6(struct tr_conf *conf, struct msghdr *mhdr, int cc, int *seq)
 			if (i % WIDTH == WIDTH - 1)
 				printf("\n");
 		}
-		if (cc % WIDTH != 0)
+		if ((cc - sizeof(*icp)) % WIDTH != 0)
 			printf("\n");
 	}
 	return(0);
```