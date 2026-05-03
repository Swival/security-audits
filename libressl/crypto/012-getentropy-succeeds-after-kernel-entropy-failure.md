# getentropy succeeds after kernel entropy failure

## Classification

Security control failure, high severity.

## Affected Locations

`arc4random/getentropy_solaris.c:148`

## Summary

`getentropy()` on Solaris failed open when both kernel urandom paths failed. Instead of returning failure, it called `getentropy_fallback()`, which hashes process and environmental metadata and returns success, causing cryptographic callers to accept non-kernel entropy.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

Both Solaris urandom collection paths fail or are unavailable:

- `/devices/pseudo/random@0:urandom`
- `/dev/urandom`

Failure can occur through open failure, read failure, or device validation failure.

## Proof

The reproduced control flow is:

- `getentropy()` first calls `getentropy_urandom()` for `/devices/pseudo/random@0:urandom`.
- If that fails, it calls `getentropy_urandom()` for `/dev/urandom`.
- `getentropy_urandom()` returns `-1` with `errno = EIO` on open, read, or device validation failure.
- After both urandom attempts fail, `getentropy()` calls `getentropy_fallback(buf, len)` instead of failing.
- `getentropy_fallback()` hashes timestamps, PIDs, load, addresses, rusage, filesystem metadata, file descriptor metadata, and previous digest state.
- `getentropy_fallback()` copies the SHA-512 digest into the caller buffer, restores `errno`, and returns `0`.

Therefore, under the stated precondition, `getentropy()` returns success even though kernel entropy collection failed.

## Why This Is A Real Bug

`getentropy()` is a cryptographic entropy control. Its callers rely on a successful return value to mean that cryptographically suitable entropy was obtained.

The fallback path is explicitly not a kernel entropy source. The source comments state that Solaris has no failsafe entropy API and list returning `EIO` or terminating as safer options, but the implemented behavior chose to “do the best under the circumstances.” That behavior converts kernel entropy failure into apparent success.

This is a fail-open security control failure: cryptographic callers cannot distinguish real kernel entropy from the fallback output.

## Fix Requirement

When both urandom collection attempts fail, `getentropy()` must not return success. It must return `-1` with `errno = EIO` or terminate the process.

## Patch Rationale

The patch removes the fallback call from the failure path. After both urandom attempts fail, `getentropy()` now sets `errno = EIO` and returns `-1`.

This preserves the API’s security contract: success is only reported when kernel urandom collection succeeds.

## Residual Risk

None

## Patch

```diff
diff --git a/arc4random/getentropy_solaris.c b/arc4random/getentropy_solaris.c
index e36426c..e50d131 100644
--- a/arc4random/getentropy_solaris.c
+++ b/arc4random/getentropy_solaris.c
@@ -135,16 +135,8 @@ getentropy(void *buf, size_t len)
 	 * providing a new failsafe API which works in a chroot or
 	 * when file descriptors are exhausted.
 	 */
-#undef FAIL_INSTEAD_OF_TRYING_FALLBACK
-#ifdef FAIL_INSTEAD_OF_TRYING_FALLBACK
-	raise(SIGKILL);
-#endif
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