# Deflate Output Ignores Negotiated MRU

## Classification

Denial of service, high severity, confidence: certain.

## Affected Locations

`net/ppp-deflate.c:565`

## Summary

PPP Deflate decompression records the negotiated MRU in `state->mru`, but `z_decompress()` did not enforce that bound on inflated output. A remote PPP peer that negotiated Deflate could send a valid-sequence compressed frame that is small on the wire but inflates far beyond `state->mru + PPP_HDRLEN`, causing repeated kernel mbuf allocation and allowing mbuf/cluster exhaustion.

## Provenance

Verified and patched from a Swival Security Scanner finding.

Scanner: https://swival.dev

## Preconditions

- PPP Deflate compression is negotiated.
- The attacker controls the remote PPP peer.
- The attacker can send valid-sequence `PPP_COMP` frames.

## Proof

`z_decomp_init()` stores the negotiated MRU in `state->mru`.

`z_decompress()` inflates attacker-supplied compressed mbufs and allocates a new output mbuf whenever `state->strm.avail_out` reaches zero. Before the patch, once decompression completed, the only MRU handling was a `DEFLATE_DEBUG` diagnostic:

```c
#ifdef DEFLATE_DEBUG
    if (olen > state->mru + PPP_HDRLEN)
	printf("ppp_deflate%d: exceeded mru (%d > %d)\n",
	       state->unit, olen, state->mru + PPP_HDRLEN);
#endif
```

The oversized packet was still accepted:

```c
*mop = mo_head;
return DECOMP_OK;
```

The reproduced trigger is a valid-sequence `PPP_COMP` frame whose raw Deflate payload starts with a compressible PPP protocol byte and expands beyond `state->mru + PPP_HDRLEN`. A raw Deflate `Z_SYNC_FLUSH` stream for roughly 1 MB of repeated bytes can compress to about 990 bytes, fitting under the default PPP MRU while causing `z_decompress()` to allocate hundreds of mbuf clusters.

The receive-side raw MRU check in `ppp_tty` limits only the encoded PPP frame at `net/ppp_tty.c:987`; it does not bound post-inflate output. The oversized decompressed mbuf chain can then reach downstream PPP receive handling, including paths at `net/if_ppp.c:1214` and `net/if_ppp.c:1223`.

For non-IP low-numbered protocols, the oversized decompressed chain is queued to `sc_inq` at `net/if_ppp.c:1437`; that queue is packet-count limited rather than byte-limited. Repeated frames can therefore retain many oversized mbuf chains and exhaust mbuf/cluster memory.

## Why This Is A Real Bug

The negotiated MRU is a protocol-enforced size limit for received PPP payloads after decompression. The vulnerable code preserved that value but treated violation as debug-only telemetry, not as an input rejection condition. Because Deflate permits very high compression ratios, a small accepted wire frame can force large kernel memory allocation before being returned as `DECOMP_OK`.

This creates a practical remote denial of service when PPP Deflate is negotiated with an attacker-controlled peer.

## Fix Requirement

Abort decompression, free the partially produced output chain, and return an error once `olen` exceeds `state->mru + PPP_HDRLEN`.

## Patch Rationale

The patch enforces the negotiated MRU in both places where inflated output length can exceed the limit:

- During output growth, immediately after completing an mbuf and increasing `olen`.
- After the final mbuf length is accounted for, before updating statistics or returning `DECOMP_OK`.

On violation, the patch frees `mo_head` with `m_freem()` and returns `DECOMP_FATALERROR`, preventing oversized decompressed packets from being accepted or queued.

## Residual Risk

None

## Patch

```diff
diff --git a/net/ppp-deflate.c b/net/ppp-deflate.c
index 7f2b332..a493416 100644
--- a/net/ppp-deflate.c
+++ b/net/ppp-deflate.c
@@ -565,6 +565,10 @@ z_decompress(void *arg, struct mbuf *mi, struct mbuf **mop)
 	    } else {
 		mo->m_len = ospace;
 		olen += ospace;
+		if (olen > state->mru + PPP_HDRLEN) {
+		    m_freem(mo_head);
+		    return DECOMP_FATALERROR;
+		}
 		MGET(mo->m_next, M_DONTWAIT, MT_DATA);
 		mo = mo->m_next;
 		if (mo == NULL) {
@@ -582,11 +586,14 @@ z_decompress(void *arg, struct mbuf *mi, struct mbuf **mop)
 	return DECOMP_ERROR;
     }
     olen += (mo->m_len = ospace - state->strm.avail_out);
+    if (olen > state->mru + PPP_HDRLEN) {
 #ifdef DEFLATE_DEBUG
-    if (olen > state->mru + PPP_HDRLEN)
 	printf("ppp_deflate%d: exceeded mru (%d > %d)\n",
 	       state->unit, olen, state->mru + PPP_HDRLEN);
 #endif
+	m_freem(mo_head);
+	return DECOMP_FATALERROR;
+    }
 
     state->stats.unc_bytes += olen;
     state->stats.unc_packets++;
```