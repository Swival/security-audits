# Curve25519 Low-Order Public Keys Accepted

## Classification

High severity cryptographic flaw.

Confidence: certain.

## Affected Locations

`sbin/iked/dh.c:752`

## Summary

`iked` accepts low-order Curve25519 peer public keys during IKE group 31 key exchange. For an all-zero 32-byte public key, `ec25519_create_shared()` computes and accepts an all-zero X25519 shared secret. That predictable DH output is then consumed by IKE key derivation instead of aborting the exchange.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched from the provided source and runtime confirmation.

## Preconditions

- Negotiated IKE DH group is group 31, Curve25519.
- Execution reaches `dh_create_shared()`.
- A remote IKE peer supplies a 32-byte low-order Curve25519 KE payload, including the all-zero public key.

## Proof

The vulnerable path is:

- `group_get()` maps `GROUP_CURVE25519` to `ec25519_create_shared()`.
- `dh_create_shared()` checks only that the peer exchange buffer length equals `dh_getlen(group)`.
- For Curve25519, `dh_getlen(group)` is 32 bytes.
- `ec25519_create_shared()` calls `crypto_scalarmult_curve25519(shared, curve25519->secret, public)`.
- The function then returns success unconditionally.

Runtime reproduction confirmed that compiling the committed Curve25519 scalar multiplication code with a fixed scalar and an all-zero 32-byte public key returned `ret=0` and produced:

```text
0000000000000000000000000000000000000000000000000000000000000000
```

That value is accepted as the DH shared secret.

## Why This Is A Real Bug

X25519 implementations must reject low-order peer inputs by detecting an all-zero shared output. Without this check, a malicious remote peer can force the shared secret to a known constant.

In this code path, the all-zero value becomes the DH output used by `ikev2_sa_keys()` as `g^ir` for SKEYSEED and IKE SA key derivation. Accepting attacker-controlled predictable DH output violates the security assumptions of the IKE key exchange.

## Fix Requirement

Reject low-order Curve25519 public keys by failing the exchange when the computed X25519 shared secret is all zero.

## Patch Rationale

The patch adds an all-zero shared-secret check immediately after `crypto_scalarmult_curve25519()` in `ec25519_create_shared()`.

This is the correct enforcement point because:

- It covers all low-order public keys that produce an all-zero X25519 output.
- It preserves the existing length validation in `dh_create_shared()`.
- It causes `dh_create_shared()` to fail through the existing `group->shared()` return path.
- It avoids trying to enumerate invalid public keys and instead checks the cryptographic result directly.

## Residual Risk

None

## Patch

```diff
diff --git a/sbin/iked/dh.c b/sbin/iked/dh.c
index 0dd32ce..c7e7e1c 100644
--- a/sbin/iked/dh.c
+++ b/sbin/iked/dh.c
@@ -754,9 +754,12 @@ ec25519_create_exchange(struct dh_group *group, uint8_t *buf)
 int
 ec25519_create_shared(struct dh_group *group, uint8_t *shared, uint8_t *public)
 {
+	static const uint8_t	 zero[CURVE25519_SIZE];
 	struct curve25519_key	*curve25519 = group->curve25519;
 
 	crypto_scalarmult_curve25519(shared, curve25519->secret, public);
+	if (timingsafe_bcmp(shared, zero, CURVE25519_SIZE) == 0)
+		return (-1);
 	return (0);
 }
```