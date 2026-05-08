# Short Probe Payload Causes Out-of-Bounds Read

## Classification

Out-of-bounds read, high severity.

Confidence: certain.

## Affected Locations

- `usr.sbin/dvmrpd/probe.c:90`
- `usr.sbin/dvmrpd/probe.c:91`
- `usr.sbin/dvmrpd/probe.c:92`
- `usr.sbin/dvmrpd/probe.c:113`

## Summary

`recv_probe()` reads a four-byte DVMRP generation ID from an attacker-controlled probe payload before verifying that the payload contains four bytes. A remote DVMRP peer can send a probe with a payload length of 0..3 bytes after the DVMRP header, causing `memcpy(&gen_id, buf, sizeof(gen_id))` to read past the received packet buffer.

Because `len` is unsigned, the subsequent subtraction also underflows and can cause the neighbor-list parser to scan far beyond the short packet.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and confirmed against the provided source and packet path.

## Preconditions

- `dvmrpd` receives a DVMRP probe on an active interface.
- The attacker can send multicast DVMRP probes as a remote DVMRP peer.
- The probe reaches `recv_probe()` with payload length below `sizeof(gen_id)`.

## Proof

A DVMRP probe with IP payload length `sizeof(struct dvmrp_hdr) + 0..3` reaches the vulnerable code path:

- `usr.sbin/dvmrpd/dvmrpe.c:165` dispatches received raw `IPPROTO_IGMP` packets to `recv_packet`.
- `usr.sbin/dvmrpd/packet.c:151` only requires the 8-byte DVMRP header to be present.
- `usr.sbin/dvmrpd/packet.c:263` only checks the DVMRP major version.
- A packet with type `0x13`, code `DVMRP_CODE_PROBE`, major version `3`, and destination `224.0.0.4` reaches `recv_probe(..., buf, len)` at `usr.sbin/dvmrpd/packet.c:203`.
- `usr.sbin/dvmrpd/probe.c:91` executes `memcpy(&gen_id, buf, sizeof(gen_id))` before checking `len`.
- For `len` values 0..3, the four-byte copy reads past the received probe payload.
- `usr.sbin/dvmrpd/probe.c:92` then subtracts four from unsigned `len`, causing underflow.
- The loop at `usr.sbin/dvmrpd/probe.c:113` can then continue parsing neighbor IDs far beyond the short packet.

## Why This Is A Real Bug

The DVMRP probe payload is attacker controlled, and the existing packet validation only guarantees that the DVMRP header is present. It does not guarantee that the probe body contains the mandatory four-byte generation ID.

`recv_probe()` assumes that `buf` contains at least `sizeof(gen_id)` bytes and performs the copy unconditionally. For short probe bodies, this is an immediate out-of-bounds read. The later neighbor-list length check cannot prevent the bug because it occurs after the invalid read and after unsigned length underflow.

The reproduced path demonstrates that a short multicast DVMRP probe reaches the vulnerable operation directly.

## Fix Requirement

Reject probe payloads shorter than `sizeof(gen_id)` before copying the generation ID or advancing `buf`.

## Patch Rationale

The patch adds an early length check immediately before the first read from the probe body:

```c
if (len < sizeof(gen_id))
	return;
```

This prevents both failure modes:

- The four-byte `memcpy()` no longer runs unless the probe body contains the full generation ID.
- The subsequent `len -= sizeof(gen_id)` can no longer underflow for short payloads.

The check is placed after the existing neighbor lookup but before any access to `buf`, preserving existing behavior for valid probes while safely ignoring malformed short probes.

## Residual Risk

None.

## Patch

```diff
diff --git a/usr.sbin/dvmrpd/probe.c b/usr.sbin/dvmrpd/probe.c
index 4046dd3..24688cc 100644
--- a/usr.sbin/dvmrpd/probe.c
+++ b/usr.sbin/dvmrpd/probe.c
@@ -88,6 +88,9 @@ recv_probe(struct iface *iface, struct in_addr src, u_int32_t src_ip,
 			break;
 	}
 
+	if (len < sizeof(gen_id))
+		return;
+
 	memcpy(&gen_id, buf, sizeof(gen_id));
 	len -= sizeof(gen_id);
 	buf += sizeof(gen_id);
```