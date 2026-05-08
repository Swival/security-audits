# Zero-Length IPCP Nak Option Loops Forever

## Classification

Denial of service, medium severity.

Confidence: certain.

## Affected Locations

`usr.sbin/pppd/ipcp.c:588`

## Summary

A malicious PPP peer can send an IPCP Configure-Nak containing an unknown option with length zero. `ipcp_nakci()` fails to reject the zero-length option before advancing through the remaining-CI loop, causing `len` and `p` to remain effectively unchanged and making `pppd` spin indefinitely during IPCP negotiation.

## Provenance

Verified from supplied source, reproducer analysis, and patch.

Originally identified by Swival Security Scanner: https://swival.dev

## Preconditions

PPP link reaches IPCP negotiation and the peer can send Configure-Nak packets with the current request id.

## Proof

`ipcp_input()` passes IPCP packets to `fsm_input()`. `fsm_input()` routes `CONFNAK` to `fsm_rconfnakrej()`, which calls the registered `ipcp_nakci()` callback after expected-id and seen-ack checks.

After `pppd` sends an IPCP Configure-Request, a malicious peer can send a Configure-Nak payload such as:

```text
7f 00 00
```

This represents an unknown option type `0x7f`, option length `0`, and one trailing byte.

In `ipcp_nakci()`:

- `while (len > CILEN_VOID)` enters when `len == 3`.
- `GETCHAR(citype, p)` reads `0x7f`.
- `GETCHAR(cilen, p)` reads attacker-controlled `0`.
- `len -= cilen` leaves `len` unchanged.
- `next = p + cilen - 2` resets `next` to the original option start.
- The unknown option falls through the `switch`.
- `p = next` restores the same pointer position.

The loop condition remains true and the same bytes are parsed forever.

## Why This Is A Real Bug

PPP option lengths are attacker-controlled input. The parser must reject option lengths smaller than the CI header size before using them to decrement the remaining length or advance the pointer.

The remaining-CI loop already assumes each option consumes at least `CILEN_VOID` bytes. Without validating that invariant, a zero-length option prevents forward progress. This is reachable from a single peer-controlled Configure-Nak during normal IPCP negotiation and prevents the callback from returning, consuming CPU and blocking IPCP progress.

## Fix Requirement

Reject any remaining Nak option with `cilen < CILEN_VOID` before subtracting it from `len` or computing the next option pointer.

## Patch Rationale

The patch adds the missing minimum-length validation immediately after reading `cilen`:

```c
if (cilen < CILEN_VOID)
    goto bad;
```

This matches the parser’s required invariant that every CI has at least a type and length byte. It prevents zero-length and one-byte options from being used in pointer arithmetic, guarantees loop progress for accepted options, and treats malformed Configure-Nak packets as bad without changing valid negotiation behavior.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/pppd/ipcp.c b/usr.sbin/pppd/ipcp.c
index d359cc7..23ea5d0 100644
--- a/usr.sbin/pppd/ipcp.c
+++ b/usr.sbin/pppd/ipcp.c
@@ -590,6 +590,8 @@ ipcp_nakci(fsm *f, u_char *p, int len)
     while (len > CILEN_VOID) {
 	GETCHAR(citype, p);
 	GETCHAR(cilen, p);
+	if (cilen < CILEN_VOID)
+	    goto bad;
 	if( (len -= cilen) < 0 )
 	    goto bad;
 	next = p + cilen - 2;
```