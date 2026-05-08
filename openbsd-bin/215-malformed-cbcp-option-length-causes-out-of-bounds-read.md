# Malformed CBCP Option Length Causes Out-Of-Bounds Read

## Classification

Out-of-bounds read. Severity: medium. Confidence: certain.

## Affected Locations

`usr.sbin/pppd/cbcp.c:271`

## Summary

`cbcp_recvreq()` parses CBCP request options without rejecting option lengths smaller than the two-byte option header. A malicious PPP peer can send a CBCP request option with `opt_len` equal to `0` or `1`, causing the packet pointer and remaining-length counter to diverge. Subsequent `GETCHAR` operations can read past the validated CBCP payload, producing a denial of service.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

`pppd` processes CBCP packets from the peer, in a build and configuration where CBCP is enabled and accepted.

## Proof

`cbcp_input()` validates only the outer CBCP packet length, subtracts the fixed CBCP header, and passes the remaining payload to `cbcp_recvreq()` for `CBCP_REQ`.

In `cbcp_recvreq()`:

- The loop requires only `len > 1`, ensuring two bytes are believed available.
- `GETCHAR(type, pckt)` and `GETCHAR(opt_len, pckt)` consume two bytes from `pckt`.
- The old validation checked only `len < opt_len`.
- For `opt_len == 0`, `pckt` advances by two bytes while `len` is not reduced.
- For `opt_len == 1`, `pckt` advances by two bytes while `len` is reduced by only one.
- Repeated malformed options make `pckt` outrun the remaining-length accounting and later reads access memory past the validated CBCP payload.

An ASan harness reproducing this parser behavior with a max-sized CBCP request filled with `{ CB_CONF_NO, 0 }` options reports a global-buffer-overflow read.

## Why This Is A Real Bug

CBCP option length includes the two-byte option header. Therefore valid CBCP options must have `opt_len >= 2`. The original code consumed those two bytes before validating the lower bound, then subtracted the attacker-controlled `opt_len` from `len`. Values `0` and `1` make the parser’s pointer position inconsistent with its length accounting, allowing reads beyond the packet buffer. The malformed packet is peer-controlled, so a malicious PPP peer can trigger the condition.

## Fix Requirement

Reject CBCP request options with `opt_len < 2` before consuming any option body fields, and keep remaining-length accounting based on validated option sizes.

## Patch Rationale

The patch adds the missing lower-bound validation:

```c
if (opt_len < 2 || len < opt_len)
    break;
```

This ensures every accepted option is at least as large as the two bytes already consumed for `type` and `opt_len`. It also preserves the existing upper-bound check that rejects options extending beyond the remaining CBCP payload.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/pppd/cbcp.c b/usr.sbin/pppd/cbcp.c
index 599d8ee..b614c32 100644
--- a/usr.sbin/pppd/cbcp.c
+++ b/usr.sbin/pppd/cbcp.c
@@ -269,7 +269,7 @@ cbcp_recvreq(cbcp_state *us, char *pckt, int pcktlen)
 	GETCHAR(type, pckt);
 	GETCHAR(opt_len, pckt);
 
-	if (len < opt_len)
+	if (opt_len < 2 || len < opt_len)
 	    break;
 	len -= opt_len;
```