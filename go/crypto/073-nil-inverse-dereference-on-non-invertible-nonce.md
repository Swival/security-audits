# Nil inverse panic in legacy ECDSA signing

## Classification
- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations
- `src/crypto/ecdsa/ecdsa_legacy.go:112`
- Patched at `src/crypto/ecdsa/ecdsa_legacy.go:119`

## Summary
`signLegacy` computes `kInv := new(big.Int).ModInverse(k, N)` for a nonce `k` derived from `randFieldElement`, but it did not check whether `ModInverse` returned `nil`. On deprecated custom curves whose order `N` is composite or otherwise admits non-invertible nonzero elements, a valid sampled `k` can be non-invertible. If `r != 0`, execution reaches `s.Mul(s, kInv)` and panics.

## Provenance
- Verified finding reproduced from source and reproducer notes
- Reference scanner: [Swival Security Scanner](https://swival.dev)

## Preconditions
- Caller uses the deprecated custom-curve signing path
- `priv.Curve.Params().N` is composite or otherwise invalid such that some `1 <= k < N` has no inverse modulo `N`
- A sampled non-invertible `k` also produces `r != 0`

## Proof
`signLegacy` loads `N := c.Params().N` and only rejects `N.Sign() == 0`. It then samples `k` via `randFieldElement`, which only enforces `1 <= k < N`. Next it executes:
```go
kInv = new(big.Int).ModInverse(k, N)
r, _ = c.ScalarBaseMult(k.Bytes())
r.Mod(r, N)
...
s.Mul(s, kInv)
```
For composite or otherwise invalid `N`, `ModInverse(k, N)` returns `nil` when `gcd(k, N) != 1`. There was no guard before `s.Mul(s, kInv)`, so a non-invertible sampled `k` causes a nil dereference panic. The reproducer confirmed this trigger path and confirmed the code lacks any primality, oddness, or non-nil inverse check.

## Why This Is A Real Bug
The panic is reachable from input-controlled signing state whenever untrusted deprecated custom curves or untrusted `ecdsa.PrivateKey` objects are accepted. This is a denial-of-service condition on the legacy custom-curve path. The issue is not theoretical: `randFieldElement` explicitly permits nonzero non-units when `N` is malformed, and `math/big`.`ModInverse` documents `nil` for non-invertible inputs.

## Fix Requirement
After computing the modular inverse, reject `nil` and retry nonce generation, or equivalently validate curve order properties before signing. The fix must prevent `kInv == nil` from reaching arithmetic use sites.

## Patch Rationale
The patch adds an immediate guard after `ModInverse`:
```diff
kInv = new(big.Int).ModInverse(k, N)
+if kInv == nil {
+    continue
+}
```
This preserves existing control flow, resamples `k`, and guarantees `s.Mul(s, kInv)` only executes with a valid inverse. It is the minimal targeted fix for the reproduced crash.

## Residual Risk
None

## Patch
```diff
diff --git a/src/crypto/ecdsa/ecdsa_legacy.go b/src/crypto/ecdsa/ecdsa_legacy.go
index 2fb1b21a60..a9e6c3b538 100644
--- a/src/crypto/ecdsa/ecdsa_legacy.go
+++ b/src/crypto/ecdsa/ecdsa_legacy.go
@@ -119,6 +119,9 @@ func signLegacy(priv *PrivateKey, csprng io.Reader, hash []byte) (sig []byte, er
 			}
 
 			kInv = new(big.Int).ModInverse(k, N)
+			if kInv == nil {
+				continue
+			}
 
 			r, _ = c.ScalarBaseMult(k.Bytes())
 			r.Mod(r, N)
```