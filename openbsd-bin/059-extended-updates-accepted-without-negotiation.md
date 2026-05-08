# Extended UPDATEs Accepted Without Negotiation

## Classification

- Type: policy bypass
- Severity: medium
- Confidence: certain

## Affected Locations

- `usr.sbin/bgpd/session_bgp.c:591`
- `usr.sbin/bgpd/session_bgp.c:605`
- `usr.sbin/bgpd/session_bgp.c:629`
- `usr.sbin/bgpd/session_bgp.c:660`
- `usr.sbin/bgpd/session_bgp.c:1248`
- `usr.sbin/bgpd/session_bgp.c:1293`
- `usr.sbin/bgpd/session_bgp.c:1442`
- `usr.sbin/bgpd/session.c:1036`
- `usr.sbin/bgpd/rde.c:1485`

## Summary

`parse_header()` selected the inbound BGP message length limit from `peer->capa.ann.ext_msg`, the local announcement flag, instead of `peer->capa.neg.ext_msg`, the negotiated capability flag. When the local peer announced extended-message support but the remote peer did not, inbound UPDATE messages larger than the standard 4096-byte BGP packet limit could be accepted and processed after session establishment.

## Provenance

- Source: Swival Security Scanner
- URL: https://swival.dev
- Status: reproduced and patched

## Preconditions

- Local peer announces `CAPA_EXT_MSG`.
- Remote BGP peer does not advertise extended-message capability.
- Negotiation therefore leaves `peer->capa.neg.ext_msg == 0`.
- Session reaches post-OPEN message processing.
- Remote peer sends an UPDATE with length `> MAX_PKTSIZE` and `<= MAX_EXT_PKTSIZE`.

## Proof

- Extended-message negotiation is computed as `p->capa.neg.ext_msg = (p->capa.ann.ext_msg && p->capa.peer.ext_msg) != 0` in `capa_neg_calc()`.
- Only enforced local configuration `p->capa.ann.ext_msg == 2` rejects a peer that did not advertise the capability.
- `parse_header()` used `peer->capa.ann.ext_msg` to raise `maxlen` from `MAX_PKTSIZE` to `MAX_EXT_PKTSIZE`.
- Therefore, if the local side merely announced extended messages, an oversized inbound UPDATE passed the generic header length check even when the remote side did not negotiate extended messages.
- Accepted UPDATEs are dispatched through `session_process_msg()` to `parse_update()` and then `session_handle_update()`, allowing route data beyond the negotiated limit to reach RDE processing.
- Outbound UPDATE sizing already uses `p->capa.neg.ext_msg`, confirming the intended policy boundary is the negotiated flag.

## Why This Is A Real Bug

The inbound acceptance policy was based on unilateral local advertisement rather than bilateral capability negotiation. BGP extended messages are only valid when both peers advertise support. A malicious established peer that omitted `CAPA_EXT_MSG` could still send oversized UPDATE messages and have them processed, bypassing the negotiated message-size limit.

## Fix Requirement

Use `peer->capa.neg.ext_msg` for post-OPEN inbound BGP message length checks so extended packet sizes are accepted only after successful bilateral negotiation.

## Patch Rationale

The patch changes the `parse_header()` length-limit decision from the local announcement flag to the negotiated capability flag. This aligns inbound UPDATE acceptance with capability negotiation and with existing outbound UPDATE sizing behavior.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/bgpd/session_bgp.c b/usr.sbin/bgpd/session_bgp.c
index 65bd9a9..8ba7325 100644
--- a/usr.sbin/bgpd/session_bgp.c
+++ b/usr.sbin/bgpd/session_bgp.c
@@ -602,7 +602,7 @@ parse_header(struct ibuf *msg, void *arg, int *fd)
 		return (NULL);
 	}
 
-	if (peer->capa.ann.ext_msg)
+	if (peer->capa.neg.ext_msg)
 		maxlen = MAX_EXT_PKTSIZE;
 
 	if (len < MSGSIZE_HEADER || len > maxlen) {
```