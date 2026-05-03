# getentropy Falls Back To Non-OS Entropy

## Classification

Security control failure, high severity.

## Affected Locations

`arc4random/getentropy_hpux.c:114`

## Summary

`getentropy()` first attempts to read entropy from `/dev/urandom`. If that OS entropy source fails, the HP-UX implementation calls `getentropy_fallback()`, which hashes process-local and system-observable state and returns success. This makes an unavailable OS entropy source appear successful to callers, allowing fallback bytes to be accepted as cryptographic entropy.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- `/dev/urandom` open, stat, or read fails.
- A caller requests entropy through this `getentropy()` implementation.

## Proof

The reproduced path is:

- `getentropy()` calls `getentropy_urandom(buf, len, "/dev/urandom", 0)`.
- If `/dev/urandom` is unavailable or fails validation/read, `getentropy_urandom()` returns `-1` with `errno = EIO`.
- The fail-closed control is disabled by `#undef FAIL_INSTEAD_OF_TRYING_FALLBACK` at `arc4random/getentropy_hpux.c:112`.
- The failure path calls `getentropy_fallback(buf, len)` at `arc4random/getentropy_hpux.c:114`.
- `getentropy_fallback()` hashes values including times, pids, pstat data, priorities, signal masks, library and stack addresses, mmap addresses, filesystem metadata, fd 0 state, and prior digest output.
- The fallback copies SHA512 output into the caller buffer and returns `0`, restoring the previous `errno`.

Result: `/dev/urandom` failure is converted into successful entropy delivery.

## Why This Is A Real Bug

`getentropy()` is the cryptographic entropy source. Its security contract requires failure when secure OS entropy cannot be obtained. Returning success with bytes derived from process-local and observable system state violates that contract because callers cannot distinguish the fallback output from real OS-provided entropy.

This is fail-open behavior in a security control: the entropy source reports success precisely when the trusted source is unavailable.

## Fix Requirement

When `/dev/urandom` is unavailable or unusable, `getentropy()` must fail closed by returning `-1` with `errno = EIO`. It must not call or accept `getentropy_fallback()` as a successful entropy source.

## Patch Rationale

The patch removes the fallback success path after `getentropy_urandom()` fails. The function now sets `errno = EIO` and returns `-1`, preserving the security boundary that only OS entropy may satisfy `getentropy()`.

This makes the existing failure condition explicit and prevents callers from accepting non-OS fallback bytes as cryptographic entropy.

## Residual Risk

None

## Patch

```diff
diff --git a/arc4random/getentropy_hpux.c b/arc4random/getentropy_hpux.c
index 7188ae5..7fc483a 100644
--- a/arc4random/getentropy_hpux.c
+++ b/arc4random/getentropy_hpux.c
@@ -113,12 +113,8 @@ getentropy(void *buf, size_t len)
 #ifdef FAIL_INSTEAD_OF_TRYING_FALLBACK
 	raise(SIGKILL);
 #endif
-	ret = getentropy_fallback(buf, len);
-	if (ret != -1)
-		return (ret);
-
 	errno = EIO;
-	return (ret);
+	return (-1);
 }
 
 static int
```