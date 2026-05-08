# Short IPCP Nak Reads Past Packet Buffer

## Classification

Out-of-bounds read, medium severity.

## Affected Locations

`usr.sbin/pppd/ipcp.c:525`

## Summary

`ipcp_nakci()` parses peer IPCP Configure-Nak packets. When VJ compression negotiation is active, the `NAKCIVJ` macro reads `p[1]` to obtain the option length before checking that the remaining Nak body contains at least two bytes. A remote PPP peer can send a zero- or one-byte Configure-Nak body and trigger a read past the supplied packet buffer during IPCP negotiation.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The local side requested VJ compression in the current IPCP state.
- The remote peer sends a matching IPCP Configure-Nak for the outstanding Configure-Request.
- The Configure-Nak body is shorter than two bytes.

## Proof

The packet path reaches the vulnerable parser:

- `ipcp_input()` passes peer IPCP packets into the FSM.
- `fsm_rconfnakrej()` dispatches Configure-Nak processing when the packet id matches the outstanding request.
- VJ negotiation is enabled by default with `wo->neg_vj = 1` in `usr.sbin/pppd/ipcp.c:201`.
- `ipcp_resetci()` copies wanted options into `ipcp_gotoptions` in `usr.sbin/pppd/ipcp.c:272`.
- In `ipcp_nakci()`, `NAKCIVJ` evaluates `go->neg_vj` and then reads `p[1]` in `((cilen = p[1]) == CILEN_COMPRESS || cilen == CILEN_VJ)` before validating `len >= cilen`.

With a Configure-Nak body length of 0 or 1 and VJ negotiation enabled, `p[1]` is outside the provided Nak body. An ASan harness using the committed `ipcp_nakci()` logic confirmed that a one-byte Nak body triggers an immediate out-of-bounds read at `p[1]`.

## Why This Is A Real Bug

The parser relies on packet-provided length data but accesses the second option-header byte before proving the option header exists. The preceding address-Nak parser can fail cleanly on a short body, after which `NAKCIVJ` is still evaluated. Because `go->neg_vj` is normally true during IPCP negotiation, a malformed remote Configure-Nak can reach the unchecked read without requiring local misconfiguration.

## Fix Requirement

Require `len >= 2` before reading `p[0]` or `p[1]` in `NAKCIVJ`.

## Patch Rationale

The patch adds `len >= 2` to the `NAKCIVJ` guard before `p[1]` is dereferenced. This preserves the existing validation order for complete option headers while ensuring short Nak bodies are rejected without reading outside the packet buffer.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/pppd/ipcp.c b/usr.sbin/pppd/ipcp.c
index d359cc7..ed057ec 100644
--- a/usr.sbin/pppd/ipcp.c
+++ b/usr.sbin/pppd/ipcp.c
@@ -525,6 +525,7 @@ ipcp_nakci(fsm *f, u_char *p, int len)
 
 #define NAKCIVJ(opt, neg, code) \
     if (go->neg && \
+	len >= 2 && \
 	((cilen = p[1]) == CILEN_COMPRESS || cilen == CILEN_VJ) && \
 	len >= cilen && \
 	p[0] == opt) { \
```