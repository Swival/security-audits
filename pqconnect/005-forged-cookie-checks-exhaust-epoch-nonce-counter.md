# Forged Cookie Checks Exhaust Epoch Nonce Counter

## Classification

Denial of service, medium severity.

## Affected Locations

`src/pqconnect/cookie/cookiemanager.py:169`

## Summary

`check_cookie` retrieves an epoch cookie key through `get_cookie_key(ts)` before authenticating attacker-supplied cookie ciphertext. `get_cookie_key` always increments that epoch's nonce counter, so forged cookies with invalid authentication tags consume nonce space even though verification fails. After enough forged checks for an active epoch, the counter reaches exhaustion and later valid cookie issuance or verification for that epoch fails with `ExhaustedNonceSpaceError`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

An attacker can send cookie-prefixed packets containing a current active epoch timestamp.

## Proof

`check_cookie` parses attacker-controlled bytes with `Cookie.from_bytes`, then reads the cookie timestamp, nonce, ciphertext, and tag. Before calling `secret_unbox`, it calls `get_cookie_key(ts)`.

In the vulnerable implementation:

- `src/pqconnect/cookie/cookiemanager.py:169` calls `get_cookie_key(ts)` during cookie verification.
- `get_cookie_key` reads the active epoch key and current counter-derived nonce.
- `get_cookie_key` unconditionally calls `_increment_nonce(ts)`.
- `_increment_nonce` raises once `(ctr + 1) >= (1 << NLEN)`.
- `NLEN` is 12, so exhaustion occurs after 4095 consumed counter values.

Because authentication happens after the nonce increment, forged cookies with invalid tags still advance the epoch counter. Repeating approximately 4095 forged cookie checks with an active timestamp exhausts the epoch counter. Subsequent key retrieval for that epoch raises `ExhaustedNonceSpaceError`, preventing valid cookie verification and current-epoch cookie issuance.

## Why This Is A Real Bug

The nonce counter is intended to track nonces consumed when issuing cookies, not failed verification attempts using client-supplied nonces. Cookie verification does not need to allocate a fresh server nonce because the nonce is already embedded in the cookie. Incrementing the epoch counter during verification lets unauthenticated remote input consume a scarce per-epoch resource before authentication succeeds.

The failure mode is externally triggerable and service-affecting: the server drops cookie resume and issuance for the exhausted epoch rather than merely rejecting the forged packets.

## Fix Requirement

Cookie key lookup for verification must not increment the epoch nonce counter. Nonce advancement should remain enabled for cookie issuance paths that allocate fresh server-generated nonces.

## Patch Rationale

The patch adds an `increment_nonce` parameter to `get_cookie_key`, defaulting to `True` to preserve existing issuing behavior. Verification calls `get_cookie_key(ts, increment_nonce=False)`, so `check_cookie` can retrieve the epoch key without consuming nonce space before `secret_unbox` authenticates the cookie.

This isolates nonce allocation to callers that actually need a fresh nonce while preserving compatibility for existing callers that rely on the previous default behavior.

## Residual Risk

None

## Patch

```diff
diff --git a/src/pqconnect/cookie/cookiemanager.py b/src/pqconnect/cookie/cookiemanager.py
index c3ce2e6..09c5a56 100644
--- a/src/pqconnect/cookie/cookiemanager.py
+++ b/src/pqconnect/cookie/cookiemanager.py
@@ -119,7 +119,9 @@ class CookieManager:
 
         self._keystore[ts]["ctr"] += 1
 
-    def get_cookie_key(self, ts: Optional[int] = None) -> tuple[bytes, bytes]:
+    def get_cookie_key(
+        self, ts: Optional[int] = None, increment_nonce: bool = True
+    ) -> tuple[bytes, bytes]:
         """Returns the key stored for the given timestamp as well as the
         current nonce. Raises a ValueError if the key does not exist.
 
@@ -134,7 +136,8 @@ class CookieManager:
             with self._mut:
                 key = self._keystore[ts]["key"]
                 nonce = self._keystore[ts]["ctr"].to_bytes(NLEN, "big")
-                self._increment_nonce(ts)
+                if increment_nonce:
+                    self._increment_nonce(ts)
 
         except KeyError as e:
             raise ValueError(f"Invalid timestamp") from e
@@ -169,7 +172,7 @@ class CookieManager:
 
         # Get cookie key and verify + decrypt
         try:
-            key, _ = self.get_cookie_key(ts)
+            key, _ = self.get_cookie_key(ts, increment_nonce=False)
             pt = secret_unbox(key, nonce, tag, ct, ts_bts)
 
         except KeyError as e:
```