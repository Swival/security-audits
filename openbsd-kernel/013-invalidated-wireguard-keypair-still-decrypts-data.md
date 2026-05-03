# Invalidated WireGuard Keypair Still Decrypts Data

## Classification

security_control_failure; high severity; confidence certain.

## Affected Locations

- `net/wg_noise.c:630`
- `net/wg_noise.c:633`

## Summary

`noise_remote_decrypt()` can accept an AEAD-valid WireGuard data packet for a retained keypair after that keypair has been invalidated. The decrypt path selects a keypair by receiver index and enforces age and receive-counter limits, but it did not enforce `kp->kp_valid` before AEAD decrypt and replay-counter acceptance.

## Provenance

Verified from the provided source, reproducer summary, and patch. Originally reported by Swival Security Scanner: https://swival.dev

## Preconditions

- A WireGuard keypair is invalidated but still retained in `r_current`, `r_previous`, or `r_next`.
- The remote peer still knows the old session key and local receiver index.
- The packet nonce has not already been received.
- The keypair has not aged past `REJECT_AFTER_TIME`.

## Proof

`noise_remote_expire_current()` invalidates retained keypairs by setting `kp_valid = 0` on `r_next` and `r_current`.

In `noise_remote_decrypt()`, the selected keypair is chosen only by `kp_local_index` from `r_current`, `r_previous`, or `r_next`. Before the patch, the tolerance check rejected only expired keypairs and exhausted receive counters:

```c
if (noise_timer_expired(&kp->kp_birthdate, REJECT_AFTER_TIME, 0) ||
    kp->kp_ctr.c_recv >= REJECT_AFTER_MESSAGES)
	goto error;
```

The function then performs AEAD decrypt with `kp->kp_recv`, accepts a fresh nonce via `noise_counter_recv()`, and can return `0`. The caller treats non-`EINVAL` decrypt results as authenticated packet processing and can deliver the decrypted inner packet after normal allowed-IP checks.

The reproduced trigger is a remote peer sending an AEAD-valid data packet using the invalidated keypair index after local invalidation, such as through the private-key update path that calls `noise_remote_expire_current()`.

## Why This Is A Real Bug

The encrypt path explicitly rejects invalid keypairs with `!kp->kp_valid`, and the decrypt path comment states that validity must be ensured before decrypt because decrypting against an invalid or zeroed keypair would be catastrophic. The decrypt implementation violated that invariant. Because invalidated keypairs remain retained for transition state, index lookup alone is insufficient authorization to authenticate data packets.

## Fix Requirement

Reject any selected keypair with `!kp->kp_valid` before AEAD decrypt and before receive-counter mutation.

## Patch Rationale

The patch adds the missing validity check to the existing decrypt tolerance gate, aligning decrypt behavior with encrypt behavior and the function’s stated security requirement. This prevents packets under invalidated retained keypairs from reaching AEAD decrypt, replay-counter acceptance, or authenticated-success handling.

## Residual Risk

None

## Patch

```diff
diff --git a/net/wg_noise.c b/net/wg_noise.c
--- a/net/wg_noise.c
+++ b/net/wg_noise.c
@@ -633,6 +633,7 @@ noise_remote_decrypt(struct noise_remote *r, uint32_t r_idx, uint64_t nonce,
 	 * are the same as the encrypt routine.
 	 *
 	 * kp_ctr isn't locked here, we're happy to accept a racy read. */
-	if (noise_timer_expired(&kp->kp_birthdate, REJECT_AFTER_TIME, 0) ||
+	if (!kp->kp_valid ||
+	    noise_timer_expired(&kp->kp_birthdate, REJECT_AFTER_TIME, 0) ||
 	    kp->kp_ctr.c_recv >= REJECT_AFTER_MESSAGES)
 		goto error;
```