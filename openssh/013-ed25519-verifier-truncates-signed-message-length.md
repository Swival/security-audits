# Ed25519 verifier truncates signed message length

## Classification

Security control failure at the API boundary; defense-in-depth (low severity for OpenSSH today, see Reachability); confidence certain.

## Affected Locations

`ed25519-openssl.c:161`

## Summary

`crypto_sign_ed25519_open` accepts `smlen` as `unsigned long long` but stores the derived message length in `size_t msglen`. On targets where `size_t` is narrower than `unsigned long long`, an oversized `smlen` can truncate `msglen`, causing OpenSSL verification to authenticate only a prefix while the logical signed-message length includes unauthenticated trailing bytes.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The target platform has `sizeof(size_t) < sizeof(unsigned long long)`, such as ILP32.
- The caller supplies an oversized `smlen`.
- The supplied signature is valid for the truncated message prefix.

## Proof

`crypto_sign_ed25519_open` first rejects only `smlen < crypto_sign_ed25519_BYTES`.

It then computes:

```c
msglen = smlen - crypto_sign_ed25519_BYTES;
```

The subtraction is performed in `unsigned long long`, but the result is assigned to `size_t`.

On ILP32, an input such as:

```c
smlen = crypto_sign_ed25519_BYTES + n + 2^32
```

causes `msglen` to truncate to `n`.

The following buffer-size check uses the already-truncated value:

```c
if (*mlen < msglen)
```

`EVP_DigestVerify` then verifies only `msglen` bytes:

```c
EVP_DigestVerify(mdctx, sm, crypto_sign_ed25519_BYTES, msg, msglen)
```

After successful verification, the function copies only that truncated prefix and returns success:

```c
*mlen = msglen;
memmove(m, msg, msglen);
ret = 0;
```

Thus a signature valid for the prefix is accepted for a claimed signed-message length that includes unauthenticated trailing bytes.

## Why This Is A Real Bug

The verifier’s security decision is based on a length value that may be narrower than the API length type. This creates a fail-open condition on affected platforms: the function can return success even though not all bytes implied by `smlen` were authenticated.

The API explicitly accepts `unsigned long long smlen`, while OpenSSL’s `EVP_DigestVerify` accepts a `size_t` message length. Without an explicit bounds check before conversion, oversized values are silently reduced on narrower `size_t` platforms.

### Reachability in OpenSSH

The only in-tree caller is `ssh_ed25519_verify` in `ssh-ed25519.c`, which already rejects `dlen >= INT_MAX - crypto_sign_ed25519_BYTES` and computes `smlen = len + dlen` with `len <= 64`. On every supported platform `INT_MAX <= SIZE_MAX`, so the `smlen` actually passed to `crypto_sign_ed25519_open` is bounded well below `SIZE_MAX` and the truncation cannot occur through normal SSH verification paths. The patch is therefore an API-boundary hardening change: it makes the function safe for any future caller that does not pre-bound `smlen`, and matches the contract suggested by the `unsigned long long` parameter type.

## Fix Requirement

Reject any `smlen` whose message portion exceeds `SIZE_MAX` before assigning it to `size_t msglen`.

## Patch Rationale

The patch adds a bounds check immediately after confirming that `smlen` is at least the signature length:

```c
if (smlen - crypto_sign_ed25519_BYTES > SIZE_MAX) {
	debug3_f("signed message too long: %llu", smlen);
	return -1;
}
```

At this point, the subtraction is safe because the prior check guarantees `smlen >= crypto_sign_ed25519_BYTES`.

This ensures the subsequent assignment to `size_t msglen` cannot truncate. As a result, the length passed to `EVP_DigestVerify`, the output length assigned to `*mlen`, and the number of bytes copied by `memmove` all match the validated message length.

## Residual Risk

None

## Patch

```diff
diff --git a/ed25519-openssl.c b/ed25519-openssl.c
index 32fc1c1..36ec1df 100644
--- a/ed25519-openssl.c
+++ b/ed25519-openssl.c
@@ -158,6 +158,10 @@ crypto_sign_ed25519_open(unsigned char *m, unsigned long long *mlen,
 		debug3_f("signed message bad length: %llu", smlen);
 		return -1;
 	}
+	if (smlen - crypto_sign_ed25519_BYTES > SIZE_MAX) {
+		debug3_f("signed message too long: %llu", smlen);
+		return -1;
+	}
 	/* Signature is first crypto_sign_ed25519_BYTES, message follows */
 	msg = sm + crypto_sign_ed25519_BYTES;
 	msglen = smlen - crypto_sign_ed25519_BYTES;
```