# Ed25519 Accepts Non-Canonical S Values

## Classification

- Type: `security_control_failure`
- Severity: High
- Confidence: Certain
- Component: Ed25519 signature verification

## Affected Locations

- `ed25519.c:1837`
- `ed25519.c:2000`
- `ed25519.c:2006`
- `ed25519.c:607`
- `ed25519.c:514`
- Reachability: `auth2-pubkey.c:223`
- Build condition: `Makefile.inc:102` when `OPENSSL=no`

## Summary

The Ed25519 verifier accepts signatures whose `S` scalar is non-canonical but congruent modulo the Ed25519 group order `L`. The verifier only rejects `S >= 2^253` via `sm[63] & 224`, then passes `S` to `sc25519_from32bytes`, which reduces it modulo `L`. This allows alternate encodings of an otherwise valid signature to verify successfully.

## Provenance

- Source: Swival Security Scanner
- Scanner URL: https://swival.dev
- Reproduction status: Reproduced
- Patch status: Patched

## Preconditions

- The verifier receives an otherwise valid Ed25519 signature.
- The vulnerable in-tree Ed25519 implementation is used.
- Build selects `ed25519.c`, which occurs when `OPENSSL=no`.

## Proof

- `auth2-pubkey.c:223` shows an SSH authentication client controls the signature input.
- `Makefile.inc:98` selects `ed25519-openssl.c` for `OPENSSL=yes`.
- `Makefile.inc:102` selects vulnerable `ed25519.c` for `OPENSSL=no`.
- `ed25519.c:2000` only checks `sm[63] & 224`, rejecting `S >= 2^253` but not all `S >= L`.
- `ed25519.c:514` defines the group order `L` as `sc25519_m`.
- `ed25519.c:2006` calls `sc25519_from32bytes(&scs, sm+32)`.
- `ed25519.c:607` shows `sc25519_from32bytes` calls `barrett_reduce`, reducing non-canonical `S` modulo `L`.
- `ed25519.c:2009` overwrites `S` with the public key before hashing, so mutating `S` does not alter `H(R,A,m)`.
- `ed25519.c:2014` uses the reduced scalar in `ge25519_double_scalarmult_vartime`.
- `ed25519.c:2017` compares the resulting `R` check against unchanged `R`.
- Runtime PoC result: adding `L` to a valid signature's `S` half produced `orig=0 mutated=0 mutated_s63=0x19`.

## Why This Is A Real Bug

Ed25519 requires signatures to use the canonical scalar encoding `0 <= S < L`. The verifier instead accepts some encodings with `S >= L` because it reduces `S` before verification. Since `S + L` is congruent to `S` modulo the group order, the group equation still validates while the byte-level signature differs. This breaks signature uniqueness and permits signature malleability for any attacker who has one valid signature.

## Fix Requirement

Reject signatures where the encoded `S` value is greater than or equal to the Ed25519 group order `L` before calling `sc25519_from32bytes`.

## Patch Rationale

The patch adds a lexicographic comparison of the little-endian `S` half against `sc25519_m` before scalar reduction. It preserves the existing high-bit check and rejects `S == L` and `S > L`, preventing `barrett_reduce` from normalizing non-canonical values into valid scalars.

## Residual Risk

None

## Patch

```diff
diff --git a/ed25519.c b/ed25519.c
index 2ba4b84..9e1c25c 100644
--- a/ed25519.c
+++ b/ed25519.c
@@ -1995,9 +1995,13 @@ int crypto_sign_ed25519_open(
   unsigned char rcheck[32];
   ge25519 get1, get2;
   sc25519 schram, scs;
+  int i;
 
   if (smlen < 64) goto badsig;
   if (sm[63] & 224) goto badsig;
+  for (i = 31;i >= 0 && sm[32 + i] == sc25519_m[i];--i)
+    ;
+  if (i < 0 || sm[32 + i] > sc25519_m[i]) goto badsig;
   if (ge25519_unpackneg_vartime(&get1,pk)) goto badsig;
 
   memmove(pkcopy,pk,32);
```