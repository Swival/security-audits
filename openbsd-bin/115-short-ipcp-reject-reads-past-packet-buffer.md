# short IPCP Reject reads past packet buffer

## Classification

out-of-bounds read; medium severity; confidence certain.

## Affected Locations

`usr.sbin/pppd/ipcp.c:690`

## Summary

`ipcp_rejci` parses peer-supplied IPCP Configure-Reject data. When local VJ compression negotiation is enabled, the `REJCIVJ` macro reads `p[1]` before verifying that the reject body contains the two-byte option header. A remote PPP peer can send a valid Configure-Reject packet with a zero- or one-byte IPCP payload and trigger a one-byte out-of-bounds read past the validated packet buffer.

## Provenance

Verified from supplied source, reproducer summary, and patch. Initially identified by Swival Security Scanner: https://swival.dev

## Preconditions

- Local IPCP requested VJ compression, so `go->neg_vj` is true.
- This is the default path: `ipcp_init` sets `wo->neg_vj = 1`, and `ipcp_resetci` copies wanted options into `ipcp_gotoptions`.
- Remote peer sends a Configure-Reject with a body shorter than two bytes and an id matching the outstanding request id.

## Proof

The remote input path reaches the vulnerable parser through:

`get_input` -> `ipcp_input` -> `fsm_input` -> `fsm_rconfnakrej` -> `ipcp_rejci`

`fsm_input` accepts a Configure-Reject packet with a valid PPP control header and body length `0` or `1`, then dispatches to `ipcp_rejci` when the id matches `f->reqid`.

Inside `ipcp_rejci`, `REJCIADDR` first checks that enough bytes remain for the full address option before accessing `p[1]`:

```c
len >= (cilen = old? CILEN_ADDRS: CILEN_ADDR) &&
p[1] == cilen &&
p[0] == opt
```

By contrast, the vulnerable `REJCIVJ` condition evaluates `p[1]` immediately after `go->neg`:

```c
if (go->neg &&
    p[1] == (old? CILEN_COMPRESS : CILEN_VJ) &&
    len >= p[1] &&
    p[0] == opt) {
```

For a Configure-Reject body of length `0` or `1`, `p[1]` is outside the validated IPCP payload. The later `len >= p[1]` check cannot protect the earlier read.

## Why This Is A Real Bug

The packet body is peer-controlled, and the parser is reachable during normal IPCP negotiation. VJ negotiation is enabled by default, making `go->neg_vj` normally true. The vulnerable expression dereferences `p[1]` before proving that the two-byte IPCP option header is present, so a short Configure-Reject body causes an out-of-bounds read relative to the accepted packet buffer.

## Fix Requirement

Check that at least two bytes remain before every access to `p[0]` or `p[1]` in the VJ Configure-Reject parser.

## Patch Rationale

The patch adds `len >= 2` before `REJCIVJ` reads `p[1]` or `p[0]`. This establishes that the option header is present before checking the option length and type. The existing `len >= p[1]` guard remains responsible for validating the full option body length after the length byte is safely read.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/pppd/ipcp.c b/usr.sbin/pppd/ipcp.c
index d359cc7..e945acb 100644
--- a/usr.sbin/pppd/ipcp.c
+++ b/usr.sbin/pppd/ipcp.c
@@ -694,6 +694,7 @@ ipcp_rejci(fsm *f, u_char *p, int len)
 
 #define REJCIVJ(opt, neg, val, old, maxslot, cflag) \
     if (go->neg && \
+	len >= 2 && \
 	p[1] == (old? CILEN_COMPRESS : CILEN_VJ) && \
 	len >= p[1] && \
 	p[0] == opt) { \
```