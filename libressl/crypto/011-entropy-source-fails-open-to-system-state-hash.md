# entropy source fails open to system-state hash

## Classification

security_control_failure, high severity, confidence certain.

## Affected Locations

`arc4random/getentropy_osx.c:135`

## Summary

`getentropy()` is the CSPRNG entropy collection control. When `/dev/urandom` cannot be opened, validated, or read, the implementation falls back to `getentropy_fallback()`, which hashes local system state with SHA512 and returns success. This fails open by accepting non-CSPRNG fallback bytes instead of rejecting unavailable kernel entropy.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

## Preconditions

`/dev/urandom` open, stat, or read fails.

## Proof

The reproduced control flow shows:

- `getentropy()` first calls `getentropy_urandom(buf, len)`.
- If `getentropy_urandom()` returns `-1`, `getentropy()` proceeds to call `getentropy_fallback(buf, len)`.
- `getentropy_fallback()` hashes system state including time, Mach time, sysctl data, pids, signal masks, process/library/stack addresses, mmap addresses, filesystem metadata, stdin metadata, and rusage.
- `getentropy_fallback()` copies the SHA512 digest into the caller buffer and returns `0`.
- Therefore, for `len <= 256`, once `/dev/urandom` fails, `getentropy()` can return success with fallback bytes that are not supplied by a CSPRNG entropy source.

## Why This Is A Real Bug

Entropy collection is the security boundary for CSPRNG seed material. If kernel entropy is unavailable, the control must fail closed. Hashing observable or partially predictable process and system state does not make the result equivalent to CSPRNG entropy. Returning `0` tells callers that secure entropy was collected when the required source actually failed.

## Fix Requirement

Fail closed when `/dev/urandom` cannot supply all requested bytes. `getentropy()` must return `-1` with `errno = EIO` instead of returning bytes from `getentropy_fallback()`.

## Patch Rationale

The patch removes the runtime fallback path from `getentropy()` after `/dev/urandom` failure. It leaves a `(void)getentropy_fallback;` reference to avoid unused-function diagnostics without invoking the unsafe fallback. The function now sets `errno = EIO` and returns `-1`, preserving the existing failure contract and preventing non-CSPRNG bytes from being accepted as entropy.

## Residual Risk

None

## Patch

```diff
diff --git a/arc4random/getentropy_osx.c b/arc4random/getentropy_osx.c
index db028d1..75d13d0 100644
--- a/arc4random/getentropy_osx.c
+++ b/arc4random/getentropy_osx.c
@@ -133,12 +133,9 @@ getentropy(void *buf, size_t len)
 #ifdef FAIL_INSTEAD_OF_TRYING_FALLBACK
 	raise(SIGKILL);
 #endif
-	ret = getentropy_fallback(buf, len);
-	if (ret != -1)
-		return (ret);
-
+	(void)getentropy_fallback;
 	errno = EIO;
-	return (ret);
+	return (-1);
 }
 
 static int
```