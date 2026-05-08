# Quick Mode HASH(3) Under-Allocates PRF Buffer

## Classification

High severity out-of-bounds write.

Confidence: certain.

## Affected Locations

`sbin/isakmpd/ike_quick_mode.c:1243`

Reproduced vulnerable path:

`sbin/isakmpd/ike_quick_mode.c:1970`

`sbin/isakmpd/ike_quick_mode.c:1971`

`sbin/isakmpd/ike_quick_mode.c:1998`

## Summary

`responder_recv_HASH()` trusts the peer-controlled Quick Mode message 3 HASH payload length when allocating `my_hash`. If an authenticated IKE peer sends a HASH payload shorter than the negotiated PRF digest size, `malloc(hash_len - ISAKMP_GEN_SZ)` creates an undersized heap buffer. `prf->Final(my_hash, prf->prfctx)` then writes the full negotiated PRF output into that undersized allocation before the truncated `memcmp()` runs.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was manually reproduced and patched.

## Preconditions

- Attacker has a valid phase 1 SA.
- Attacker reaches Quick Mode message 3 as the remote IKE peer.
- Attacker sends a short HASH payload body in Quick Mode message 3.

## Proof

The reproduced execution path is:

- Quick Mode message 3 contains only a HASH payload and dispatches through `ipsec_responder()` to `ike_quick_mode_responder[2]`.
- Parsing only enforces the HASH payload minimum size, not equality with the negotiated PRF digest size.
- Active non-Informational exchanges skip generic HASH verification.
- `responder_recv_HASH()` reads `hash_len = GET_ISAKMP_GEN_LENGTH(hash)`.
- It allocates `my_hash = malloc(hash_len - ISAKMP_GEN_SZ)`.
- It finalizes the PRF with `prf->Final(my_hash, prf->prfctx)`.
- The PRF writes `hash->hashsize` bytes, while supported hash sizes are 16-64 bytes.
- A HASH body of 1 byte therefore causes a heap out-of-bounds write before `memcmp()` compares only the attacker-sized length.

## Why This Is A Real Bug

The HASH payload length is attacker-controlled after phase 1 authentication. The allocation size is derived from that length, but the write size is derived from the negotiated PRF digest size. Those sizes can differ. When the peer supplies a shorter HASH body than the negotiated digest, the PRF finalization writes past the end of `my_hash`.

This is not blocked earlier because the reproduced parser path accepts minimally sized HASH payloads and does not validate Quick Mode HASH length against the negotiated hash size before `responder_recv_HASH()`.

## Fix Requirement

Before allocation or PRF finalization, require the HASH payload length to equal:

```c
ISAKMP_GEN_SZ + hash_get(isa->hash)->hashsize
```

Reject mismatched lengths with `ISAKMP_NOTIFY_INVALID_HASH_INFORMATION`.

## Patch Rationale

The patch adds an exact length check immediately after reading `hash_len` and before allocating `my_hash`. This ensures the buffer allocated for `my_hash` is exactly the negotiated PRF digest size, matching the number of bytes written by `prf->Final()`.

Rejecting malformed lengths before allocation also prevents truncated HASH comparisons from accepting attacker-controlled partial lengths.

## Residual Risk

None

## Patch

```diff
diff --git a/sbin/isakmpd/ike_quick_mode.c b/sbin/isakmpd/ike_quick_mode.c
index 354ccc5..15c5405 100644
--- a/sbin/isakmpd/ike_quick_mode.c
+++ b/sbin/isakmpd/ike_quick_mode.c
@@ -1968,6 +1968,11 @@ responder_recv_HASH(struct message *msg)
 	hash = hashp->p;
 	hashp->flags |= PL_MARK;
 	hash_len = GET_ISAKMP_GEN_LENGTH(hash);
+	if (hash_len != ISAKMP_GEN_SZ + hash_get(isa->hash)->hashsize) {
+		message_drop(msg, ISAKMP_NOTIFY_INVALID_HASH_INFORMATION, 0,
+		    1, 0);
+		goto cleanup;
+	}
 	my_hash = malloc(hash_len - ISAKMP_GEN_SZ);
 	if (!my_hash) {
 		log_error("responder_recv_HASH: malloc (%lu) failed",
```