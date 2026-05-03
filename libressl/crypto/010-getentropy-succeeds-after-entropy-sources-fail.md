# getentropy Succeeds After Entropy Sources Fail

## Classification

Security control failure; high severity.

## Affected Locations

`arc4random/getentropy_linux.c:165`

## Summary

`getentropy()` fails open when all kernel-backed entropy sources fail. After `getrandom`, `/dev/urandom`, and `SYS__sysctl` all fail, the function calls `getentropy_fallback()` and returns success if that fallback returns success. The fallback deterministically hashes process state, clocks, addresses, filesystem metadata, and optional auxv values, then returns `0`, causing callers to accept fallback digest bytes as entropy.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- `getrandom` fails.
- `/dev/urandom` fails.
- `SYS__sysctl` entropy collection fails or is unavailable.
- Caller requests a valid entropy length, `len <= 256`.

## Proof

`getentropy()` first rejects only oversized requests with `len > 256`. Valid requests proceed through the kernel entropy sources:

- `arc4random/getentropy_linux.c:105` tries `getentropy_getrandom()` and returns only on success.
- `arc4random/getentropy_linux.c:116` tries `getentropy_urandom()` and returns only on success.
- `arc4random/getentropy_linux.c:139` tries `getentropy_sysctl()` and returns only on success when `SYS__sysctl` is available.

After these sources fail, the fail-closed path is disabled by:

```c
#undef FAIL_INSTEAD_OF_TRYING_FALLBACK
```

The function then calls:

```c
ret = getentropy_fallback(buf, len);
if (ret != -1)
	return (ret);
```

`getentropy_fallback()` hashes local process and system-observable state, copies digest bytes into `buf`, restores `errno`, and returns `0`. Therefore, when no trusted entropy source is available, `getentropy()` still reports success.

## Why This Is A Real Bug

`getentropy()` is the entropy-source primitive for `arc4random`. Its callers rely on failure reporting when the system cannot provide usable entropy. Returning success with fallback bytes changes a hard entropy-source failure into accepted pseudo-entropy.

The fallback material is not equivalent to kernel entropy. It is derived from process state, timing, addresses, filesystem metadata, and optional auxiliary vector values. In the stated failure condition, this deterministic fallback allows the entropy control to fail open instead of rejecting the request.

## Fix Requirement

Fail closed after all kernel entropy sources fail. Do not return fallback bytes as successful entropy.

## Patch Rationale

The patch removes the call to `getentropy_fallback()` from the failure path and makes `getentropy()` return `-1` with `errno = EIO` after all kernel entropy sources fail. This preserves existing success behavior for `getrandom`, `/dev/urandom`, and `SYS__sysctl`, while ensuring the no-entropy condition is reported to callers.

## Residual Risk

None

## Patch

```diff
diff --git a/arc4random/getentropy_linux.c b/arc4random/getentropy_linux.c
index c7c39c2..c869955 100644
--- a/arc4random/getentropy_linux.c
+++ b/arc4random/getentropy_linux.c
@@ -168,12 +168,8 @@ getentropy(void *buf, size_t len)
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
 
 #if defined(SYS_getrandom) && defined(GRND_NONBLOCK)
```