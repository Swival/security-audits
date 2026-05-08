# Ed25519 Verifier Accepts Noncanonical S

## Classification

Cryptographic flaw; signature malleability; medium severity; confidence: certain.

## Affected Locations

`usr.bin/ssh/ed25519.c:1734`

`usr.bin/ssh/ed25519.c:607`

`usr.bin/ssh/ed25519.c:1999`

`usr.bin/ssh/ed25519.c:2002`

`usr.bin/ssh/ed25519.c:2014`

`usr.bin/ssh/ed25519.c:2017`

`usr.bin/ssh/Makefile.inc:102`

## Summary

The fallback Ed25519 verifier accepted signatures whose `S` scalar encoding was greater than or equal to the Ed25519 group order `L`, as long as the top three bits were clear. The verifier then reduced `S` modulo `L` via `sc25519_from32bytes`, allowing a distinct noncanonical signature such as `S + L` to verify against the same message and public key.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

A remote peer can supply a verifier input containing an otherwise valid Ed25519 signature.

The original valid signature has `S < 2^253 - L`, so replacing `S` with little-endian `S + L` keeps `sm[63] & 224` clear.

The vulnerable fallback implementation is built, e.g. `OPENSSL=no`.

## Proof

`crypto_sign_ed25519_open` first rejects only `sm[63] & 224`, which checks the top three bits but does not enforce `S < L`.

It then calls `sc25519_from32bytes(&scs, sm+32)`, and `sc25519_from32bytes` calls `barrett_reduce`, reducing the supplied 32-byte scalar modulo `L`.

The hash input is `R || pk || message`; changing only `S` does not change `hram`.

Verification uses the reduced `scs` in `ge25519_double_scalarmult_vartime`. Therefore a signature with `S' = S + L` produces the same scalar value, same `rcheck`, and passes `crypto_verify_32`.

The reproducer confirmed acceptance of a distinct noncanonical signature for the same message.

## Why This Is A Real Bug

Ed25519 signatures require canonical scalar encodings with `0 <= S < L`. Accepting `S >= L` violates the signature format and enables signature malleability: an attacker possessing any suitable valid signature can construct a different accepted signature without the private key.

The path is reachable in builds using the bundled fallback Ed25519 implementation: `usr.bin/ssh/Makefile.inc:102` selects `ed25519.c` for `OPENSSL=no`.

## Fix Requirement

Reject any signature whose 32-byte little-endian `S` value is greater than or equal to the Ed25519 group order before calling `sc25519_from32bytes`.

## Patch Rationale

The patch compares `sm[32..63]` against `sc25519_m`, the existing little-endian group order constant.

The comparison runs from the most significant byte to the least significant byte. It rejects immediately if `S > L`, accepts continuation if `S < L`, and rejects equality after the loop. This enforces `S < L` before the existing modulo-reduction routine can normalize a noncanonical scalar.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/ssh/ed25519.c b/usr.bin/ssh/ed25519.c
index 2ba4b84..42ea193 100644
--- a/usr.bin/ssh/ed25519.c
+++ b/usr.bin/ssh/ed25519.c
@@ -1995,9 +1995,16 @@ int crypto_sign_ed25519_open(
   unsigned char rcheck[32];
   ge25519 get1, get2;
   sc25519 schram, scs;
+  int i;
 
   if (smlen < 64) goto badsig;
   if (sm[63] & 224) goto badsig;
+  for(i=31;i>=0;i--)
+  {
+    if (sm[32+i] > sc25519_m[i]) goto badsig;
+    if (sm[32+i] < sc25519_m[i]) break;
+  }
+  if (i < 0) goto badsig;
   if (ge25519_unpackneg_vartime(&get1,pk)) goto badsig;
 
   memmove(pkcopy,pk,32);
```