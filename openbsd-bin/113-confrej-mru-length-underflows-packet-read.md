# ConfRej MRU length underflows packet read

## Classification

Out-of-bounds read, medium severity.

Confidence: certain.

## Affected Locations

`usr.sbin/npppd/npppd/lcp.c:812`

## Summary

`lcp_rejci` parses peer-controlled LCP Configure-Reject options. For `PPP_LCP_MRU`, it accepts any option length that passes the generic packet-bound check, then unconditionally reads a two-byte MRU value with `GETSHORT`. A malicious peer can send an MRU Configure-Reject option with length `2`, which contains only the option header and no MRU value, causing a two-byte read past the received LCP packet boundary.

## Provenance

Verified from the provided source, reproduced with an ASan harness, and patched according to the supplied fix.

Source: Swival Security Scanner, https://swival.dev

## Preconditions

- The peer can participate in PPP LCP negotiation with `npppd`.
- `npppd` has sent an LCP Configure-Request containing an MRU option.
- The peer can send a matching LCP Configure-Reject for that requested MRU option.

## Proof

The reproduced path is:

- `lcp_addci` emits an MRU option and marks MRU as requested.
- `fsm_input` dispatches a valid LCP Configure-Reject to `fsm_rconfnakrej`.
- `fsm_rconfnakrej` calls `lcp_rejci` when the response id matches `reqid`.
- `lcp_rejci` reads attacker-controlled `type` and `len`.
- A malformed MRU reject option with bytes `01 02` has `type = PPP_LCP_MRU` and `len = 2`.
- The generic check `len <= 0 || remlen() + 2 < len` passes because the two-byte option is fully inside the packet.
- The MRU case then calls `GETSHORT(mru, inp)` even though no value bytes remain.
- With the MRU reject option at packet end, `GETSHORT` reads two bytes past the received LCP packet boundary.
- A small ASan harness using this two-byte MRU reject option reports a heap-buffer-overflow on the `GETSHORT` read.

## Why This Is A Real Bug

The parser correctly validates exact lengths for other fixed-size LCP options, including MRU in `lcp_reqci`, `lcp_ackci`, `lcp_proxy_recv_ci`, and `lcp_proxy_sent_ci`. The ConfRej MRU parser is the outlier: it performs the MRU value read without first requiring `len == 4`.

The generic bounds check only proves the declared option is inside the received packet. It does not prove the option contains the two MRU value bytes required by `GETSHORT`. Therefore, `len = 2` is accepted structurally but is too short for the subsequent read.

## Fix Requirement

Require `len == 4` before processing `PPP_LCP_MRU` in `lcp_rejci`.

## Patch Rationale

The patch adds the same exact-length validation already used by the other MRU parsers. A Configure-Reject for MRU must include the full rejected option, whose MRU option length is four bytes: one byte type, one byte length, and two bytes value.

Rejecting any other MRU length prevents `GETSHORT` from reading beyond the option while preserving valid Configure-Reject behavior.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/npppd/npppd/lcp.c b/usr.sbin/npppd/npppd/lcp.c
index e132670..321274e 100644
--- a/usr.sbin/npppd/npppd/lcp.c
+++ b/usr.sbin/npppd/npppd/lcp.c
@@ -810,6 +810,8 @@ lcp_rejci(fsm *f, u_char *inp, int inlen)
 			inp += 4;
 			break;
 		case PPP_LCP_MRU:
+			if (len != 4)
+				goto fail;
 			LCP_OPT_REJECTED(mru);
 			GETSHORT(mru, inp);
 			break;
```