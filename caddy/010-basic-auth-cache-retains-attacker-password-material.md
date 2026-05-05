# Basic Auth Cache Retains Attacker Password Material

## Classification

Denial of service, medium severity, confidence certain.

## Affected Locations

`modules/caddyhttp/caddyauth/basicauth.go:176`

## Summary

When HTTP Basic Auth `hash_cache` is enabled, attacker-controlled plaintext passwords are copied into retained cache keys. Large unique passwords can force the process to retain large map keys until random eviction, creating attacker-driven memory pressure and potential process memory exhaustion.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- A protected route uses HTTP Basic Auth.
- `hash_cache` is enabled for that route.
- An unauthenticated HTTP client can reach the protected route.

## Proof

`Authenticate` reads attacker-supplied Basic Auth credentials via `req.BasicAuth()` and passes the plaintext password to `correctPassword`.

With `HashCache` enabled, `correctPassword` originally built the cache key as:

```go
cacheKey := hex.EncodeToString(append(account.password, plaintextPassword...))
```

This copies the attacker-controlled password into a string key retained by `HashCache.cache`.

The issue is reachable even for failed authentication. If the username does not exist, `Authenticate` assigns `account.password = hba.fakePassword` and still calls `correctPassword`, so unauthenticated requests with invalid users can populate the cache before receiving `401`.

A reproduced same-package test confirmed that one request with a 1 MiB Basic Auth password creates one cache entry whose key length is:

```text
2 * (len(fakePassword) + len(password))
```

The factor of two comes from hex encoding. Unique large passwords miss the cache and are stored until eviction, which only begins after the map already has 1000 entries.

## Why This Is A Real Bug

The cache is intended to bound entry count, not entry size. Because each key contains unbounded attacker-controlled password bytes, an attacker can retain large amounts of memory with a small number of requests. Random eviction after 1000 entries still leaves roughly a 900-1000-entry retained window, so plausible large request-header inputs are enough to cause significant process memory growth.

This is not limited to valid users or successful authentication. Nonexistent users also traverse the vulnerable cache path.

## Fix Requirement

Cache keys must not retain unbounded attacker-controlled password material. The key must either be fixed-size or password input must be bounded before storage.

## Patch Rationale

The patch replaces the hex-encoded concatenation with a SHA-256 digest of the same input tuple:

```go
cacheKeyHash := sha256.Sum256(append(account.password, plaintextPassword...))
cacheKey := string(cacheKeyHash[:])
```

This preserves the cache semantics while making every retained cache key fixed-size. The cache still keys on both the stored account hash and plaintext password, but no longer stores the plaintext password bytes themselves or grows with attacker input length.

The patch also removes the no-longer-needed `encoding/hex` import and adds `crypto/sha256`.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/caddyhttp/caddyauth/basicauth.go b/modules/caddyhttp/caddyauth/basicauth.go
index 4152d790..f6b221b2 100644
--- a/modules/caddyhttp/caddyauth/basicauth.go
+++ b/modules/caddyhttp/caddyauth/basicauth.go
@@ -15,8 +15,8 @@
 package caddyauth
 
 import (
+	"crypto/sha256"
 	"encoding/base64"
-	"encoding/hex"
 	"encoding/json"
 	"fmt"
 	weakrand "math/rand/v2"
@@ -172,8 +172,9 @@ func (hba HTTPBasicAuth) correctPassword(account Account, plaintextPassword []by
 		return compare()
 	}
 
-	// compute a cache key that is unique for these input parameters
-	cacheKey := hex.EncodeToString(append(account.password, plaintextPassword...))
+	// compute a fixed-size cache key that is unique for these input parameters
+	cacheKeyHash := sha256.Sum256(append(account.password, plaintextPassword...))
+	cacheKey := string(cacheKeyHash[:])
 
 	// fast track: if the result of the input is already cached, use it
 	hba.HashCache.mu.RLock()
```