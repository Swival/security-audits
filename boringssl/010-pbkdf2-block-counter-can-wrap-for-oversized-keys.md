# PBKDF2 oversized output request wraps 32-bit block counter

## Classification
- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations
- `crypto/evp/pbkdf.cc:62`

## Summary
`PKCS5_PBKDF2_HMAC` derives PBKDF2 output one digest-sized block at a time using a 32-bit block counter encoded into `i_buf`. The implementation accepted any `size_t key_len` without checking whether the request required more than `UINT32_MAX` blocks. On 64-bit builds, sufficiently large `key_len` values cause the counter to wrap from `0xffffffff` to `0`, producing invalid and repeated block-index inputs and therefore deterministic wrong derived key material.

## Provenance
- Verified from the provided finding and reproducer against the implementation in `crypto/evp/pbkdf.cc`
- Scanner source: https://swival.dev

## Preconditions
- `key_len` exceeds `UINT32_MAX * EVP_MD_size(digest)`
- Execution occurs on a build where `size_t` can represent that threshold, i.e. practically 64-bit targets
- Caller provides a correspondingly large output buffer and invokes the exported PBKDF2 API directly

## Proof
The function iterates over output blocks with a 32-bit counter `i`, encoding each value into `i_buf` for the PBKDF2 `INT(i)` input. There was no pre-loop bound ensuring the requested output fits within the PBKDF2 limit of `UINT32_MAX` blocks. Once `i` reaches `0xffffffff`, the next increment wraps to `0x00000000`, which is not a valid PBKDF2 block index and collides with prior semantics rather than extending derivation correctly. This causes deterministic incorrect output for oversized requests.

The reproducer narrowed reachability correctly:
- In-tree callers do not pass attacker-controlled lengths at this scale
- On 32-bit builds, `size_t` cannot represent the threshold
- On 64-bit builds, the condition is still reachable through the public API with intentionally huge requests; with built-in 16-byte digests, the threshold is about 64 GiB

## Why This Is A Real Bug
PBKDF2 defines block derivation over a positive 32-bit block index space. Returning output after counter wrap violates the algorithm and yields wrong key material instead of rejecting an impossible request. This is a correctness and API-contract bug in exported cryptographic functionality, even though the trigger requires extreme sizes.

## Fix Requirement
Reject requests whose `key_len` would require more than `UINT32_MAX` PBKDF2 blocks before entering the derivation loop.

## Patch Rationale
The patch in `010-pbkdf2-block-counter-can-wrap-for-oversized-keys.patch` adds a precondition check in `crypto/evp/pbkdf.cc` that computes the digest block size and fails early when `key_len` exceeds the maximum representable PBKDF2 output for a 32-bit block counter. This preserves valid behavior for all supported requests and prevents counter wrap and malformed block-index encoding.

## Residual Risk
None

## Patch
```diff
diff --git a/crypto/evp/pbkdf.cc b/crypto/evp/pbkdf.cc
index 1111111..2222222 100644
--- a/crypto/evp/pbkdf.cc
+++ b/crypto/evp/pbkdf.cc
@@ -1,6 +1,7 @@
 #include <openssl/evp.h>
 
 #include <limits.h>
+#include <stdint.h>
 
 #include <openssl/hmac.h>
 #include <openssl/mem.h>
@@ -59,6 +60,13 @@ int PKCS5_PBKDF2_HMAC(const char *password, size_t password_len,
   uint32_t i = 1;
   int md_len = EVP_MD_size(digest);
 
+  if (md_len <= 0) {
+    return 0;
+  }
+
+  if (key_len / (size_t)md_len >= UINT32_MAX) {
+    return 0;
+  }
+
   while (key_len > 0) {
     uint8_t digest_tmp[EVP_MAX_MD_SIZE];
     uint8_t i_buf[4];
```