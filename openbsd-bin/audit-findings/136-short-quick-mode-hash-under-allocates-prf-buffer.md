# Short Quick Mode HASH Under-Allocates PRF Buffer

## Classification

Out-of-bounds write. Severity: high. Confidence: certain.

## Affected Locations

`sbin/isakmpd/ike_quick_mode.c:1515`

## Summary

`responder_recv_HASH_SA_NONCE()` trusted the attacker-supplied Quick Mode HASH payload length when allocating `my_hash`, then wrote a full negotiated PRF digest into that buffer. A short HASH payload could therefore allocate fewer bytes than the PRF finalizer writes, causing a heap out-of-bounds write before HASH validation rejects the message.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

An attacker has an established ISAKMP SA and sends Quick Mode message 1 with HASH first and a short HASH payload length.

## Proof

The responder path obtains the HASH payload and reads:

- `hash_len = GET_ISAKMP_GEN_LENGTH(hash)`
- `my_hash = malloc(hash_len - ISAKMP_GEN_SZ)`
- `prf->Final(my_hash, prf->prfctx)`

The PRF finalizer writes the full negotiated HMAC digest, independent of the attacker-controlled HASH payload length. Reproduction confirmed that a HASH payload length of 5 allocates 1 byte, while negotiated HMAC-MD5/SHA/SHA2 writes at least 16 bytes. The overflow occurs before `memcmp()` rejects the invalid HASH.

Relevant evidence:

- Quick Mode responder verifies HASH in `responder_recv_HASH_SA_NONCE()`.
- Generic HASH validation is skipped for active non-informational exchanges.
- PRF finalizers write full digest sizes, with supported hash sizes from 16 to 64 bytes.
- The invalid HASH is rejected only after `prf->Final()` has already written past the short allocation.

## Why This Is A Real Bug

The allocation size is attacker-controlled, but the write size is determined by the negotiated PRF digest size. These sizes can diverge. Because the write occurs before authentication failure handling, an authenticated IKE peer that completed phase 1 can trigger a heap overwrite by sending a short Quick Mode HASH payload.

## Fix Requirement

Before allocating the PRF output buffer, require the HASH payload length to exactly equal the generic ISAKMP payload header size plus the negotiated hash digest size.

## Patch Rationale

The patch validates:

```c
hash_len == ISAKMP_GEN_SZ + hash_get(isa->hash)->hashsize
```

before `malloc()` and before `prf->Final()`. Invalid HASH lengths are rejected with `ISAKMP_NOTIFY_INVALID_HASH_INFORMATION`, preventing under-allocation while preserving the existing HASH verification flow for correctly sized payloads.

## Residual Risk

None

## Patch

```diff
diff --git a/sbin/isakmpd/ike_quick_mode.c b/sbin/isakmpd/ike_quick_mode.c
index 354ccc5..0da46f5 100644
--- a/sbin/isakmpd/ike_quick_mode.c
+++ b/sbin/isakmpd/ike_quick_mode.c
@@ -1513,6 +1513,11 @@ responder_recv_HASH_SA_NONCE(struct message *msg)
 		goto cleanup;
 	}
 	hash_len = GET_ISAKMP_GEN_LENGTH(hash);
+	if (hash_len != ISAKMP_GEN_SZ + hash_get(isa->hash)->hashsize) {
+		message_drop(msg, ISAKMP_NOTIFY_INVALID_HASH_INFORMATION, 0,
+		    1, 0);
+		goto cleanup;
+	}
 	my_hash = malloc(hash_len - ISAKMP_GEN_SZ);
 	if (!my_hash) {
 		log_error("responder_recv_HASH_SA_NONCE: malloc (%lu) failed",
```