# Oversized DATA Length Desynchronizes Sndio Client

## Classification

Denial of service, medium severity.

## Affected Locations

`lib/libsndio/aucat.c:71`

## Summary

An attacker-controlled or compromised sndio server can send an `AMSG_DATA` header with a declared payload size larger than `AMSG_DATAMAX`. The client accepts that length, enters `RSTATE_DATA`, and then consumes subsequent protocol messages as data until the oversized `rtodo` counter reaches zero. This desynchronizes protocol handling and can stall the client.

## Provenance

Verified and reproduced from the supplied finding. Scanner provenance: Swival Security Scanner, https://swival.dev

Confidence: certain.

## Preconditions

- The client connects to an attacker-controlled or compromised sndio server.
- The malicious peer can send crafted sndio protocol messages.
- The peer sends `AMSG_DATA` with `u.data.size > AMSG_DATAMAX`.

## Proof

`_aucat_rmsg` reads a complete `struct amsg` from `hdl->fd`. When the command is `AMSG_DATA`, the original code copies `ntohl(hdl->rmsg.u.data.size)` into `hdl->rtodo` and switches to `RSTATE_DATA` without validating the size against `AMSG_DATAMAX`.

`_aucat_rdata` then reads from the socket as payload until `hdl->rtodo` reaches zero. Only after that does it restore `RSTATE_MSG` and resume normal message parsing.

A socketpair PoC confirmed the behavior: after an oversized `AMSG_DATA` header followed by an `AMSG_FLOWCTL` header, `_aucat_rdata` consumed the `AMSG_FLOWCTL` header as data and left the handle in `RSTATE_DATA` with 4096 bytes still pending.

No later generic bound prevents this. Audio paths reject only zero or frame-unaligned sizes, so an attacker can choose an oversized aligned length. MIDI accepts `AMSG_DATA` directly.

## Why This Is A Real Bug

The wire protocol already limits data message payloads with `AMSG_DATAMAX`, and the write side enforces that limit in `_aucat_wdata`. The read side failed to enforce the same invariant.

Because receive state is driven by the untrusted declared length, an oversized value causes the client to interpret later control messages as data. This is a protocol desynchronization bug with practical denial-of-service impact: normal control-message processing is prevented while the client drains attacker-declared payload bytes.

## Fix Requirement

Reject inbound `AMSG_DATA` messages whose declared size exceeds `AMSG_DATAMAX`.

## Patch Rationale

The patch adds the missing read-side validation immediately after identifying an inbound `AMSG_DATA` message and before copying the untrusted size into `hdl->rtodo`.

If `u.data.size > AMSG_DATAMAX`, `_aucat_rmsg` logs the protocol error, marks EOF, and returns failure. This prevents entry into `RSTATE_DATA` with an invalid payload length and preserves protocol synchronization.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/libsndio/aucat.c b/lib/libsndio/aucat.c
index ee1a460..51d0159 100644
--- a/lib/libsndio/aucat.c
+++ b/lib/libsndio/aucat.c
@@ -69,6 +69,11 @@ _aucat_rmsg(struct aucat *hdl, int *eof)
 		hdl->rtodo -= n;
 	}
 	if (ntohl(hdl->rmsg.cmd) == AMSG_DATA) {
+		if (ntohl(hdl->rmsg.u.data.size) > AMSG_DATAMAX) {
+			DPRINTF("_aucat_rmsg: data too large\n");
+			*eof = 1;
+			return 0;
+		}
 		hdl->rtodo = ntohl(hdl->rmsg.u.data.size);
 		hdl->rstate = RSTATE_DATA;
 	} else {
```