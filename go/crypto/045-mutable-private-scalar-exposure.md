# Mutable Private Scalar Exposure

## Classification

Invariant violation, medium severity. Confidence: certain.

## Affected Locations

`src/crypto/internal/fips140/ecdh/ecdh.go:30`

## Summary

`PrivateKey.Bytes` returned `priv.d` directly, exposing the mutable backing slice for the validated private scalar. A caller with access to `crypto/internal/fips140/ecdh.PrivateKey` could mutate the scalar after `NewPrivateKey` validated it, causing later ECDH operations to use an invalid or mismatched scalar.

## Provenance

Verified from Swival Security Scanner finding: https://swival.dev

## Preconditions

Caller can obtain a `PrivateKey` from `crypto/internal/fips140/ecdh` and call `PrivateKey.Bytes` before calling `ECDH`.

## Proof

`NewPrivateKey` validates that the private scalar satisfies `0 < d < n` and stores a clone of the input bytes.

Before the patch, `PrivateKey.Bytes` returned the stored slice directly:

```go
return priv.d
```

This allowed mutation of the validated scalar:

```go
priv, _ := ecdh.NewPrivateKey(c, one)

two := make([]byte, len(c.N))
two[len(two)-1] = 2
peer, _ := ecdh.NewPrivateKey(c, two)

// Mutates priv.d because Bytes returns the backing slice.
copy(priv.Bytes(), c.N)

// ECDH now uses the mutated scalar without private scalar validation.
_, err := ecdh.ECDH(c, priv, peer.PublicKey())
```

Setting the scalar to zero or exactly `N` creates a value that `NewPrivateKey` would reject. `ECDH` then passes the mutated `k.d` to scalar multiplication without revalidating the private scalar.

## Why This Is A Real Bug

The key object is intended to preserve the validation invariant established by `NewPrivateKey`. Returning the internal scalar slice lets callers mutate that state after validation, making the object represent an invalid private key or a private scalar that no longer matches its public key.

This can cause invalid ECDH behavior, ECDH errors when scalar multiplication produces the point at infinity, or silent mismatch between the stored private scalar and derived public key.

The public `crypto/ecdh.PrivateKey.Bytes` wrapper returns a copy, so this is not exposed through that public API path. The bug remains real for callers that can directly use `crypto/internal/fips140/ecdh.PrivateKey`.

## Fix Requirement

`PrivateKey.Bytes` must return a copy of the private scalar, not the internal mutable slice.

## Patch Rationale

The patch changes `PrivateKey.Bytes` to return `bytes.Clone(priv.d)`. This preserves the existing API behavior of returning the private scalar bytes while preventing callers from mutating the internal validated scalar.

## Residual Risk

None

## Patch

`045-mutable-private-scalar-exposure.patch`

```diff
diff --git a/src/crypto/internal/fips140/ecdh/ecdh.go b/src/crypto/internal/fips140/ecdh/ecdh.go
--- a/src/crypto/internal/fips140/ecdh/ecdh.go
+++ b/src/crypto/internal/fips140/ecdh/ecdh.go
@@ -27,7 +27,7 @@ type PrivateKey struct {
 }
 
 func (priv *PrivateKey) Bytes() []byte {
-	return priv.d
+	return bytes.Clone(priv.d)
 }
 
 func (priv *PrivateKey) PublicKey() *PublicKey {
```