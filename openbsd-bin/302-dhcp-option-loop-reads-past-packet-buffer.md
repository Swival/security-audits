# DHCP Option Loop Reads Past Packet Buffer

## Classification

Out-of-bounds read, medium severity.

Confidence: certain.

## Affected Locations

- `usr.sbin/vmd/dhcp.c:115`

## Summary

`dhcp_request()` parses guest-supplied DHCP options after validating the DHCP magic cookie. The option loop dereferences `*op` in the loop condition before proving that `op` is still inside the packet option buffer. A crafted DHCP option whose declared length exactly consumes the remaining options region advances `op` to `oe`; the next loop iteration then reads one byte at `oe`, past the packet buffer.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched from the provided source and patch evidence.

## Preconditions

- A malicious VM guest can send DHCP traffic through vionet.
- The packet is accepted by `dhcp_request()`.
- The packet contains a valid DHCP options magic cookie.
- The DHCP options region contains a non-pad, non-end option whose length exactly reaches the end of the guest-supplied packet buffer.
- No `DHO_END` option is required.

## Proof

`usr.sbin/vmd/dhcp.c:105` derives `optslen` from the caller-supplied `buflen`, and `usr.sbin/vmd/dhcp.c:110` only requires the DHCP magic cookie before option parsing begins.

The original loop at `usr.sbin/vmd/dhcp.c:115` is:

```c
while (*op != DHO_END && op + 1 < oe) {
```

This evaluates `*op` before checking that `op` is within `[opts, oe)`.

A crafted packet can place a non-pad, non-end DHCP option after the cookie with a length that exactly consumes the remaining options region. The original bounds check:

```c
if (op + 2 + op[1] > oe)
	break;
```

allows the exact-end case. The parser then executes:

```c
op += 2 + op[1];
```

which sets `op == oe`. On the next loop iteration, `*op` reads `buf[buflen]`, one byte past the guest-supplied packet buffer.

The reproduced example shows this is reachable at the minimum accepted Ethernet frame size: `optslen` can be 36, so cookie plus option code plus length 30 plus 30 data bytes lands exactly on `oe`.

## Why This Is A Real Bug

The parser reads outside the bounds of the packet buffer before validating the pointer. The packet contents and option length are guest-controlled, and the path is reachable from accepted VM DHCP traffic with only a valid DHCP cookie.

The immediate impact is a one-byte out-of-bounds read in the vmd device process. If the guest arranges the descriptor so `buf + buflen` lies at the end of the shared guest-memory mapping, the read can cross the mapping boundary and crash the process, causing guest-triggered denial of service.

## Fix Requirement

The DHCP option parser must:

- Check `op < oe` before dereferencing `*op`.
- Ensure the option length byte exists before reading `op[1]`.
- Ensure the declared option payload length fits entirely within `[op, oe)`.
- Preserve normal parsing behavior for valid options, pad options, and `DHO_END`.

## Patch Rationale

The patch changes the loop condition from:

```c
while (*op != DHO_END && op + 1 < oe)
```

to:

```c
while (op < oe && *op != DHO_END)
```

This guarantees `op` is in bounds before dereferencing `*op`.

The patch also changes the per-option bounds check from:

```c
if (op + 2 + op[1] > oe)
```

to:

```c
if (op + 1 >= oe || op[1] > oe - op - 2)
```

This first proves the length byte exists, then validates the declared payload length using remaining-buffer arithmetic. As a result, an option that exactly reaches `oe` is processed safely, and the next loop iteration exits because `op < oe` is false before any dereference.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/vmd/dhcp.c b/usr.sbin/vmd/dhcp.c
index 0990763..093e4c1 100644
--- a/usr.sbin/vmd/dhcp.c
+++ b/usr.sbin/vmd/dhcp.c
@@ -112,12 +112,12 @@ dhcp_request(struct virtio_dev *dev, char *buf, size_t buflen, char **obuf)
 			memset(&requested_addr, 0, sizeof(requested_addr));
 			op = opts + DHCP_OPTIONS_COOKIE_LEN;
 			oe = opts + optslen;
-			while (*op != DHO_END && op + 1 < oe) {
+			while (op < oe && *op != DHO_END) {
 				if (op[0] == DHO_PAD) {
 					op++;
 					continue;
 				}
-				if (op + 2 + op[1] > oe)
+				if (op + 1 >= oe || op[1] > oe - op - 2)
 					break;
 				if (op[0] == DHO_DHCP_MESSAGE_TYPE &&
 				    op[1] == 1)
```