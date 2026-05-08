# Oversized IPCP Reject Leaks Stack

## Classification

Information disclosure; high severity.

## Affected Locations

`usr.sbin/npppd/npppd/ipcp.c:333`

## Summary

`ipcp_reqci` can return uninitialized stack bytes to a remote PPP peer during IPCP negotiation. When an attacker sends an IPCP Configure-Request with payload length greater than 128 bytes, the function prepares a Configure-Reject using the attacker-controlled request buffer, but the reject-send path incorrectly copies from an uninitialized local stack buffer instead.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- `npppd` processes attacker-supplied IPCP Configure-Request packets.
- The remote PPP peer reaches IPCP negotiation.
- The attacker sends an IPCP Configure-Request with payload length greater than 128 bytes.

## Proof

`fsm_input` receives IPCP packets and passes the Configure-Request payload pointer and length into `ipcp_reqci`.

In `ipcp_reqci`:

- `usr.sbin/npppd/npppd/ipcp.c:197` declares `rejbuf0[256]` as an uninitialized stack buffer.
- For `*lpktp > 128`, `usr.sbin/npppd/npppd/ipcp.c:216` sets `rcode = CONFREJ`, `rejbuf = pktp`, and `lrej = *lpktp`, then jumps to `fail`.
- The `CONFREJ` branch at `usr.sbin/npppd/npppd/ipcp.c:336` copies `lrej` bytes from `rejbuf0` into `pktp0`.
- `fsm.c` sends the modified payload as the Configure-Reject, and `ppp.c` transmits it via `send_packet`.

A 129-byte IPCP payload is below normal/default MRUs, so the output size check does not block transmission. The attacker receives stack bytes in the IPCP Configure-Reject.

## Why This Is A Real Bug

The oversized-request path explicitly chooses the original peer-supplied packet as the reject payload by assigning `rejbuf = pktp` and `lrej = *lpktp`. The send path ignores that selected buffer and instead copies from `rejbuf0`, which has not been initialized on that path. Because the copied bytes are transmitted back to the peer, this is a remotely triggerable stack disclosure.

## Fix Requirement

The Configure-Reject path must copy from the active reject buffer selected by the request parser, not always from the local stack buffer. Equivalently, any fallback implementation must ensure the source buffer is initialized and the copied length is bounded.

## Patch Rationale

The patch changes the `CONFREJ` copy source from `rejbuf0` to `rejbuf`.

This preserves existing behavior for normal rejected options, where `rejbuf` still points to `rejbuf0`, and fixes the oversized-request path, where `rejbuf` points to the original incoming packet. The Configure-Reject now contains the intended rejected request bytes instead of uninitialized stack memory.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/npppd/npppd/ipcp.c b/usr.sbin/npppd/npppd/ipcp.c
index f2f16ef..7682d67 100644
--- a/usr.sbin/npppd/npppd/ipcp.c
+++ b/usr.sbin/npppd/npppd/ipcp.c
@@ -333,7 +333,7 @@ fail:
 	switch (rcode) {
 	case CONFREJ:
 		IPCP_DBG((f, LOG_DEBUG, "SendConfRej"));
-		memmove(pktp0, rejbuf0, lrej);
+		memmove(pktp0, rejbuf, lrej);
 		*lpktp = lrej;
 		break;
 	case CONFNAK:
```