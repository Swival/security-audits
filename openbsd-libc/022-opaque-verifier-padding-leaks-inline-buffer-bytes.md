# Opaque Verifier Padding Leaks Inline Buffer Bytes

## Classification

Information disclosure, medium severity.

## Affected Locations

`rpc/rpc_callmsg.c:78`

## Summary

The `xdr_callmsg` XDR encode fast path reserves rounded-up verifier storage with `RNDUP(cb_verf.oa_length)` but copies only the verifier payload bytes. When the verifier length is not four-byte aligned, the remaining XDR padding bytes are left uninitialized and become part of the serialized RPC call, disclosing stale inline buffer contents to the receiving RPC peer.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- `xdr_callmsg` is encoding an RPC call.
- `XDR_ENCODE` uses the inline `XDR_INLINE` fast path.
- `cmsg->rm_call.cb_verf.oa_length` is non-zero and not four-byte aligned.
- The underlying inline output buffer contains prior non-zero bytes in the padding region.

## Proof

The inline encode path reserves space for the full rounded verifier encoding:

```c
buf = XDR_INLINE(xdrs, 8 * BYTES_PER_XDR_UNIT
	+ RNDUP(cmsg->rm_call.cb_cred.oa_length)
	+ 2 * BYTES_PER_XDR_UNIT
	+ RNDUP(cmsg->rm_call.cb_verf.oa_length));
```

The verifier branch then writes only the actual verifier bytes:

```c
memcpy((caddr_t)buf, oa->oa_base, oa->oa_length);
```

It does not clear `RNDUP(oa->oa_length) - oa->oa_length` padding bytes.

The reproducer confirmed the behavior with a 3-byte verifier and an output buffer prefilled with `0x53`. The serialized verifier bytes were:

```text
56 45 52 53
```

The first three bytes are the verifier payload `VER`; the fourth byte is stale buffer data and is transmitted as XDR padding.

## Why This Is A Real Bug

XDR opaque values are serialized with zero padding to a four-byte boundary. The non-inline `xdr_opaque` path already performs this padding clear, but the inline `xdr_callmsg` fast path bypasses it for the verifier. Inline encode advances the stream by the full rounded reservation, so unwritten padding bytes are included in the final RPC record. A malicious RPC peer receiving calls can observe these stale bytes whenever the victim sends a call with a non-word-aligned verifier.

## Fix Requirement

The verifier inline encode path must zero the XDR padding bytes after copying the verifier payload, or it must delegate verifier encoding to `xdr_opaque_auth`/`xdr_opaque`, which already emits zero padding.

## Patch Rationale

The patch preserves the existing inline fast path and explicitly clears only the verifier padding region:

```c
memset((caddr_t)buf + oa->oa_length, 0,
    RNDUP(oa->oa_length) - oa->oa_length);
```

This matches XDR opaque padding semantics and prevents stale buffer bytes from being serialized. For aligned verifier lengths, the computed padding length is zero, so behavior is unchanged.

## Residual Risk

None

## Patch

```diff
diff --git a/rpc/rpc_callmsg.c b/rpc/rpc_callmsg.c
index 5825a0e..aa7d8d7 100644
--- a/rpc/rpc_callmsg.c
+++ b/rpc/rpc_callmsg.c
@@ -81,6 +81,8 @@ xdr_callmsg(XDR *xdrs, struct rpc_msg *cmsg)
 			IXDR_PUT_LONG(buf, oa->oa_length);
 			if (oa->oa_length) {
 				memcpy((caddr_t)buf, oa->oa_base, oa->oa_length);
+				memset((caddr_t)buf + oa->oa_length, 0,
+				    RNDUP(oa->oa_length) - oa->oa_length);
 				/* no real need....
 				buf += RNDUP(oa->oa_length) / sizeof (int32_t);
 				*/
```