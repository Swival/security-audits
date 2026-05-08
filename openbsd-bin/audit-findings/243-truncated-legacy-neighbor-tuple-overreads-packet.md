# Truncated Legacy Neighbor Tuple Overreads Packet

## Classification

Out-of-bounds read, medium severity.

## Affected Locations

`usr.sbin/mrinfo/mrinfo.c:193`

## Summary

`mrinfo` accepts legacy `DVMRP_NEIGHBORS` replies and passes the received IGMP payload directly to `accept_neighbors()`. The parser only checks `p < ep` before reading a 7-byte tuple header and then reads 4-byte neighbor addresses according to `ncount` without verifying that those bytes remain. A truncated malicious reply can make `mrinfo` read past the received packet buffer and crash.

## Provenance

Verified by reproduction and patch review. Scanner provenance: Swival Security Scanner, https://swival.dev

Confidence: certain.

## Preconditions

- Victim runs `mrinfo` against a malicious multicast router.
- The malicious router replies with an `IGMP_DVMRP` `DVMRP_NEIGHBORS` message.
- The reply has `igmp_group == 0`, causing `main()` to call `accept_neighbors()`.

## Proof

`main()` accepts `DVMRP_NEIGHBORS` replies and calls:

```c
accept_neighbors(src, dst, (u_char *)(igmp + 1), igmpdatalen, ntohl(group));
```

In `accept_neighbors()`, `ep` is set to `p + datalen`, but the loop only requires `p < ep` before parsing:

```c
while (p < ep) {
        GET_ADDR(laddr);
        metric = *p++;
        thresh = *p++;
        ncount = *p++;
        while (--ncount >= 0) {
                GET_ADDR(neighbor);
        }
}
```

A payload with 1 to 6 remaining bytes enters the loop and overreads during the 7-byte tuple header. A payload with a complete tuple header but fewer than 4 bytes remaining for a declared neighbor overreads during `GET_ADDR(neighbor)`.

The reproduced crashing case used a valid-length `DVMRP_NEIGHBORS` reply with IP total length `8192`, a 20-byte IP header, an 8-byte IGMP header, and `8164` bytes of legacy-neighbor payload. The payload contained 9 valid tuples with `ncount = 225`, consuming `8163` bytes, followed by one trailing byte. The top-level loop entered with `p < ep`; `GET_ADDR(laddr)` consumed the final byte and read past `ep`, which was also `recv_buf + 8192`. An ASan harness confirmed a heap-buffer-overflow on the read past the allocated receive buffer.

## Why This Is A Real Bug

The parser treats attacker-controlled packet contents as structurally complete after only a one-byte availability check. `GET_ADDR()` performs four byte reads and the tuple header requires seven bytes total, so truncated but otherwise accepted network input deterministically advances beyond `ep`. Because `ep` can coincide with the end of the allocated receive buffer, this is a true heap out-of-bounds read, not just parsing of stale in-packet data. The practical impact is attacker-triggered denial of service of the `mrinfo` client.

## Fix Requirement

Before reading each legacy neighbor tuple header, verify that at least 7 bytes remain. Before reading each neighbor address declared by `ncount`, verify that at least 4 bytes remain. Reject or stop parsing truncated payloads.

## Patch Rationale

The patch adds the required bounds checks immediately before the corresponding reads:

```c
if (ep - p < 7)
        return;
```

before reading `laddr`, `metric`, `thresh`, and `ncount`; and:

```c
if (ep - p < 4)
        return;
```

before each neighbor `GET_ADDR(neighbor)`.

These checks preserve normal parsing for complete packets and stop processing before any truncated tuple or neighbor address can overread the receive buffer.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/mrinfo/mrinfo.c b/usr.sbin/mrinfo/mrinfo.c
index 41e3a7e..87f990e 100644
--- a/usr.sbin/mrinfo/mrinfo.c
+++ b/usr.sbin/mrinfo/mrinfo.c
@@ -191,6 +191,8 @@ accept_neighbors(u_int32_t src, u_int32_t dst, u_char *p, int datalen,
 		u_int32_t laddr;
 		int ncount;
 
+		if (ep - p < 7)
+			return;
 		GET_ADDR(laddr);
 		laddr = htonl(laddr);
 		metric = *p++;
@@ -199,6 +201,8 @@ accept_neighbors(u_int32_t src, u_int32_t dst, u_char *p, int datalen,
 		while (--ncount >= 0) {
 			u_int32_t neighbor;
 
+			if (ep - p < 4)
+				return;
 			GET_ADDR(neighbor);
 			neighbor = htonl(neighbor);
 			printf("  %s -> ", inet_fmt(laddr, s1));
```