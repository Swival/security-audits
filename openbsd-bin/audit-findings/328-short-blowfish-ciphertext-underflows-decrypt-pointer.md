# Short Blowfish Ciphertext Underflows Decrypt Pointer

## Classification

Out-of-bounds write. Severity: high. Confidence: certain.

## Affected Locations

`sbin/isakmpd/crypto.c:148`

## Summary

`crypto_decrypt()` accepted ciphertext lengths shorter than the selected cipher block size. With Blowfish-CBC selected, a length below 8 reaches `blf_decrypt()`, where pointer arithmetic backs the decrypt pointer before the packet buffer and subsequent block writes corrupt memory.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- Blowfish-CBC transform is negotiated.
- A remote IKE peer sends encrypted payload data with length below the Blowfish block size.
- The short ciphertext reaches `crypto_decrypt()` on an established ISAKMP SA.

## Proof

For encrypted packets on an existing SA, message handling calls:

- `crypto_decrypt(ks, buf + ISAKMP_HDR_SZ, sz - ISAKMP_HDR_SZ)` at `sbin/isakmpd/message.c:1412`
- `crypto_decrypt(ks, buf + ISAKMP_HDR_SZ, sz - ISAKMP_HDR_SZ)` at `sbin/isakmpd/message.c:1420`
- `crypto_decrypt(ks, buf + ISAKMP_HDR_SZ, sz - ISAKMP_HDR_SZ)` at `sbin/isakmpd/message.c:1432`

Blowfish-CBC is a supported transform using block size 8 and `blf_decrypt()` at `sbin/isakmpd/crypto.c:60` and `sbin/isakmpd/crypto.c:62`.

In `blf_decrypt()`, short input causes unsafe arithmetic:

```c
data += len - blocksize;
```

When `len < blocksize`, `len - blocksize` underflows. The function then writes decrypted words through the underflowed pointer:

```c
SET_32BIT_BIG(data, xl);
SET_32BIT_BIG(data + 4, xr);
```

Because `i` is `u_int16_t`, assigning `len - blocksize` wraps to a large value, making the loop walk and write backward past the packet allocation.

## Why This Is A Real Bug

CBC-mode ciphertext must contain a whole number of blocks and cannot be shorter than one block. The original `crypto_decrypt()` performed no length validation before:

- copying the previous ciphertext block from `buf + len - ks->xf->blocksize`
- dispatching to the transform-specific decrypt function

For Blowfish-CBC, this made a malformed remote packet capable of causing out-of-bounds writes before the packet buffer. The reachable impact is daemon memory corruption and denial of service by a malicious IKE peer after Blowfish-CBC SA establishment.

## Fix Requirement

Reject decryption requests when the ciphertext length is:

- smaller than the selected transform block size
- not an exact multiple of the selected transform block size

The validation must occur before any IV update or transform-specific decrypt call.

## Patch Rationale

The patch adds a centralized guard in `crypto_decrypt()`:

```c
if (len < ks->xf->blocksize || len % ks->xf->blocksize)
	return;
```

This prevents both unsafe pointer underflow and malformed partial-block CBC decryptions for all configured block ciphers. Placing the check before the IV copy also prevents `buf + len - blocksize` from being evaluated on invalid short input.

## Residual Risk

None

## Patch

```diff
diff --git a/sbin/isakmpd/crypto.c b/sbin/isakmpd/crypto.c
index e415461..3d5a87f 100644
--- a/sbin/isakmpd/crypto.c
+++ b/sbin/isakmpd/crypto.c
@@ -298,6 +298,8 @@ crypto_decrypt(struct keystate *ks, u_int8_t *buf, u_int16_t len)
 {
 	LOG_DBG_BUF((LOG_CRYPTO, 70, "crypto_decrypt: before decryption", buf,
 	    len));
+	if (len < ks->xf->blocksize || len % ks->xf->blocksize)
+		return;
 	/*
 	 * XXX There is controversy about the correctness of updating the IV
 	 * like this.
```