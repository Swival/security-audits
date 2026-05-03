# Uncompressed TCP State Update Reads Unchecked IP Header

## Classification

Out-of-bounds read, high severity.

## Affected Locations

`net/slcompress.c:418`

## Summary

The VJ TCP uncompressed decompression path reads IPv4 header fields before proving that the received buffer contains an IPv4 header. A malicious SLIP/PPP peer can send a valid `TYPE_UNCOMPRESSED_TCP` / `PPP_VJC_UNCOMP` frame with a truncated or empty VJ payload, causing the kernel to access bytes beyond the received packet buffer while selecting decompression state.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

VJ TCP decompression is enabled on an attacker-controlled SLIP/PPP link.

## Proof

The reproduced path shows attacker-controlled packet bytes reaching `sl_uncompress_tcp_core` without an IPv4-header-length guarantee:

- `sl_uncompress_tcp` passes the received buffer and length directly to `sl_uncompress_tcp_core(cp, len, len, type, comp, ...)`.
- `net/ppp_tty.c:871` only requires the PPP frame to contain the PPP header plus FCS before stripping FCS.
- A valid-FCS `PPP_VJC_UNCOMP` frame with zero VJ/IP payload can therefore reach the core with `buflen == 0`.
- In `TYPE_UNCOMPRESSED_TCP`, `net/slcompress.c` casts `buf` to `struct ip *` and reads `ip->ip_p` before any `buflen` validation.
- The first size validation occurs later, after `ip->ip_p` is read and, for in-range values, after `ip->ip_p = IPPROTO_TCP` writes through the unchecked pointer.

Trigger: a malicious PPP peer sends a valid-FCS `PPP_VJC_UNCOMP` frame with less than `sizeof(struct ip)` bytes after the PPP header, including the zero-payload case.

## Why This Is A Real Bug

The vulnerable code dereferences `struct ip` fields from an attacker-controlled buffer before verifying that the buffer contains a complete IPv4 header. Because the receive path can deliver `buflen == 0` or other values smaller than `sizeof(struct ip)`, the `ip->ip_p` access is outside the received packet bounds. This is a concrete kernel out-of-bounds access reachable by a malicious link peer, not a theoretical parser inconsistency.

## Fix Requirement

Validate that `buflen >= sizeof(struct ip)` before casting the buffer to `struct ip *` or reading any IPv4 header field in the `TYPE_UNCOMPRESSED_TCP` case.

## Patch Rationale

The patch adds the missing minimum IPv4 header length check at the start of the `TYPE_UNCOMPRESSED_TCP` case:

```c
if (buflen < sizeof(struct ip))
	goto bad;
```

This rejects truncated uncompressed VJ TCP frames before any `struct ip` field is read or modified. Existing later checks still validate the declared IP header length, TCP header presence, maximum reconstructed header size, and full received header availability.

## Residual Risk

None

## Patch

```diff
diff --git a/net/slcompress.c b/net/slcompress.c
index 12907da..e900282 100644
--- a/net/slcompress.c
+++ b/net/slcompress.c
@@ -474,6 +474,8 @@ sl_uncompress_tcp_core(u_char *buf, int buflen, int total_len, u_int type,
 	switch (type) {
 
 	case TYPE_UNCOMPRESSED_TCP:
+		if (buflen < sizeof(struct ip))
+			goto bad;
 		ip = (struct ip *) buf;
 		if (ip->ip_p >= MAX_STATES)
 			goto bad;
```