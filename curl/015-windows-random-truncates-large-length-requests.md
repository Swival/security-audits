# Windows random truncates large length requests

## Classification

Integer truncation, low severity, certain confidence. Hardening; no realistic in-tree caller is affected.

## Affected Locations

`lib/rand.c:42` (`Curl_win32_random`)

## Summary

`Curl_win32_random` accepts a `size_t length` and forwards it to `BCryptGenRandom` via a narrowing `(ULONG)length` cast. On Win64 `size_t` is 64-bit but `ULONG` is 32-bit, so any request larger than `ULONG_MAX` is silently truncated. Because the function zeroes the entire caller buffer first and reports `CURLE_OK` when CNG succeeds, the trailing bytes past the truncated length stay at zero while the function claims the buffer was filled with random data.

No in-tree caller currently passes a length that exceeds `ULONG_MAX`, so the practical impact today is zero. The bug is filed as a hardening fix to prevent a future caller from receiving a partially-zero "random" buffer with a success return code.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

Verified from source review.

## Preconditions

- Windows build (64-bit, `LLP64`).
- A caller invokes `Curl_win32_random` with `length > ULONG_MAX` (i.e. >= 4 GiB).

No such call site exists in the current source tree; this is a contract violation between an internal API and a hypothetical future caller.

## Proof

`Curl_win32_random` zeroes the caller buffer for the full requested length:

```c
memset(entropy, 0, length);
```

It then calls Windows CNG with a truncated length:

```c
if(BCryptGenRandom(NULL, entropy, (ULONG)length,
                   BCRYPT_USE_SYSTEM_PREFERRED_RNG) != STATUS_SUCCESS)
  return CURLE_FAILED_INIT;

return CURLE_OK;
```

On Win64, with `length == 0x100000010`, `(ULONG)length` is `0x10`. CNG fills 16 bytes; the remaining bytes retain the earlier zero fill. The function returns `CURLE_OK`, indicating success.

## Why This Is A Real Bug

A function whose entire purpose is to fill a buffer with cryptographic random bytes must not return success when it left a predictable zero tail in the caller buffer. The bug lives in the function itself: it produces the zero fill, applies a lossy narrowing cast, and returns success without verifying that the request was satisfied. Even if no caller exercises the affected length today, the API surface is wrong: any future caller that requests more than 4 GiB will get a silently broken result.

## Fix Requirement

Reject requests larger than the range the underlying RNG primitive accepts before zeroing the buffer or calling the RNG.

## Patch Rationale

The patch adds an explicit upper bound check:

```c
if(length > ULONG_MAX)
  return CURLE_FAILED_INIT;
```

This converts the silent truncation into an explicit failure, so the function only reports success when the entire requested length was passed to `BCryptGenRandom`.

## Residual Risk

None. The check matches the parameter type of the underlying CNG API.

## Patch

```diff
diff --git a/lib/rand.c b/lib/rand.c
index dd82750ba6..6076c10138 100644
--- a/lib/rand.c
+++ b/lib/rand.c
@@ -41,6 +41,9 @@
 
 CURLcode Curl_win32_random(unsigned char *entropy, size_t length)
 {
+  if(length > ULONG_MAX)
+    return CURLE_FAILED_INIT;
+
   memset(entropy, 0, length);
 
   if(BCryptGenRandom(NULL, entropy, (ULONG)length,
```
