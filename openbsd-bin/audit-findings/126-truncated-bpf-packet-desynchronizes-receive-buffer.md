# Truncated BPF Packet Desynchronizes Receive Buffer

## Classification

Denial of service, medium severity.

Confidence: certain.

## Affected Locations

`usr.sbin/dhcrelay6/bpf.c:368`

## Summary

`receive_packet()` mishandles BPF records where `bh_caplen != bh_datalen`. The truncated-packet path advances `rbuf_offset` incorrectly by assigning `hdr.bh_hdrlen = hdr.bh_caplen`, leaving the receive cursor inside the current BPF record instead of moving to the next aligned record. A remote host on the relay’s link can trigger this with an accepted DHCPv6 frame that BPF truncates, causing subsequent parsing to treat packet payload bytes as a `struct bpf_hdr` and desynchronize the receive buffer.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced from source inspection and comparison with the adjacent DHCPv4 BPF handling pattern.

## Preconditions

- `dhcrelay6` listens on an attacker-reachable link.
- The attacker can send DHCPv6 frames accepted by the installed BPF filter.
- BPF returns an accepted frame with `bh_caplen != bh_datalen`.

## Proof

In `usr.sbin/dhcrelay6/bpf.c`, `receive_packet()` stores BPF reads in `interface->rbuf` and parses each record from `interface->rbuf_offset`.

For truncated records, the vulnerable branch is:

```c
if (hdr.bh_caplen != hdr.bh_datalen) {
	interface->rbuf_offset += hdr.bh_hdrlen =
	    hdr.bh_caplen;
	continue;
}
```

At this point `rbuf_offset` still points at the BPF header. The code should skip the BPF header plus captured data, rounded to BPF alignment. Instead, it assigns `hdr.bh_hdrlen` to `hdr.bh_caplen` and advances only by `caplen`.

After this branch, `receive_packet()` can return `0` because `length` is nonzero, while `interface->rbuf_offset` remains inside the captured packet. On the next receive path, the refill guard checks only equality:

```c
if (interface->rbuf_offset == interface->rbuf_len)
```

Because the cursor is neither equal to the buffer length nor positioned at the next record, the function copies a `struct bpf_hdr` from attacker-controlled packet bytes and continues through the unchecked decode path, including `decode_hw_header()` in `usr.sbin/dhcrelay6/packet.c:147` and later offset adjustments in `usr.sbin/dhcrelay6/bpf.c:388`.

The adjacent DHCPv4 BPF code shows the expected behavior at `usr.sbin/dhcpd/bpf.c:321`.

## Why This Is A Real Bug

The receive loop depends on `rbuf_offset` always pointing to the start of a valid BPF record or exactly to `rbuf_len`. The truncated-packet branch violates that invariant. Once desynchronized, subsequent iterations parse arbitrary payload bytes as BPF metadata, allowing bogus header lengths, bogus captured lengths, out-of-bounds offset calculations, record discard, and relay disruption.

The trigger is remote under the stated preconditions because the attacker only needs to send a DHCPv6 frame that passes the BPF filter and is returned truncated by BPF.

## Fix Requirement

When dropping a truncated BPF record, advance past the current record using:

- the current `rbuf_offset`,
- `hdr.bh_hdrlen`,
- `hdr.bh_caplen`,
- BPF word alignment.

The code must not assign to `hdr.bh_hdrlen`.

## Patch Rationale

The patch restores the BPF record cursor invariant by moving `interface->rbuf_offset` to the aligned end of the current captured record:

```c
interface->rbuf_offset = BPF_WORDALIGN(
    interface->rbuf_offset + hdr.bh_hdrlen + hdr.bh_caplen);
```

This matches BPF record layout semantics and prevents the next iteration from interpreting packet payload bytes as a `struct bpf_hdr`.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/dhcrelay6/bpf.c b/usr.sbin/dhcrelay6/bpf.c
index ea3a133..c1f4b15 100644
--- a/usr.sbin/dhcrelay6/bpf.c
+++ b/usr.sbin/dhcrelay6/bpf.c
@@ -355,8 +355,9 @@ receive_packet(struct interface_info *interface, unsigned char *buf,
 		 * do is drop it.
 		 */
 		if (hdr.bh_caplen != hdr.bh_datalen) {
-			interface->rbuf_offset += hdr.bh_hdrlen =
-			    hdr.bh_caplen;
+			interface->rbuf_offset = BPF_WORDALIGN(
+			    interface->rbuf_offset + hdr.bh_hdrlen +
+			    hdr.bh_caplen);
 			continue;
 		}
```