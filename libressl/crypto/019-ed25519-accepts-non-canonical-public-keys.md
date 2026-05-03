# Ed25519 accepts non-canonical public keys

## Classification

Cryptographic flaw, high severity.

## Affected Locations

`curve25519/curve25519.c:1025`

## Summary

`ED25519_verify()` accepted non-canonical Ed25519 public-key encodings whose encoded `y` coordinate is greater than or equal to the field modulus `p = 2^255 - 19`. The verifier hashed the original attacker-supplied public-key bytes, but decoded the key through `fe_frombytes()`, which reduces the field element modulo `p` instead of rejecting non-canonical encodings. This allowed aliased public-key encodings to participate in valid signature verification.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

The verifier accepts attacker-supplied `public_key` bytes.

## Proof

`ED25519_verify()` passes `public_key` directly to `x25519_ge_frombytes_vartime()`.

`x25519_ge_frombytes_vartime()` decodes the encoded `Y` coordinate with `fe_frombytes()`. `fe_frombytes()` ignores the top bit and normalizes limbs modulo `p`, but does not reject encodings where the 255-bit field value is `>= p`.

A concrete non-canonical public key:

```text
ee ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 7f
```

This encodes `p + 1`, which reduces to `y = 1`, the identity point. The reproducer showed `x25519_ge_frombytes_vartime()` accepted it and `ED25519_verify()` returned success.

With `R = B`:

```text
58 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66
```

and `S = 1`, the verification equation becomes `[1]B + h*(-identity) = B`, so verification succeeds for an arbitrary message. The harness printed:

```text
decode=0 verify=1
```

Reachability is practical because callers pass raw bytes to `ED25519_verify()`, and the EVP path stores public keys after length checks only before calling it at `ec/ecx_methods.c:868`.

## Why This Is A Real Bug

RFC8032 decoding requires rejection of non-canonical field encodings. The implementation instead accepts an encoding such as `p + 1`, reduces it to a valid point, and verifies group arithmetic against the reduced point while hashing the unreduced attacker-supplied public-key bytes. This creates observable acceptance of signatures under aliased, non-canonical public keys.

## Fix Requirement

Reject Ed25519 public-key encodings whose encoded `Y` field element is `>= p` before calling `fe_frombytes()`.

## Patch Rationale

The patch adds a canonical field-encoding check at the start of `x25519_ge_frombytes_vartime()`. Because the sign bit occupies the top bit of `s[31]`, the comparison masks that bit with `0x7f` and rejects values at or above the little-endian encoding of `p = 2^255 - 19`:

```text
ed ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 7f
```

This prevents non-canonical `Y` encodings from reaching `fe_frombytes()` while preserving canonical encodings and the existing curve-point validation.

## Residual Risk

None

## Patch

```diff
diff --git a/curve25519/curve25519.c b/curve25519/curve25519.c
index 0aa3d28..131785e 100644
--- a/curve25519/curve25519.c
+++ b/curve25519/curve25519.c
@@ -989,6 +989,14 @@ int x25519_ge_frombytes_vartime(ge_p3 *h, const uint8_t *s) {
   fe v3;
   fe vxx;
   fe check;
+  int i;
+
+  if ((s[31] & 0x7f) == 0x7f) {
+    for (i = 30; i > 0 && s[i] == 0xff; i--)
+      ;
+    if (i == 0 && s[0] >= 0xed)
+      return -1;
+  }
 
   fe_frombytes(h->Y, s);
   fe_1(h->Z);
```