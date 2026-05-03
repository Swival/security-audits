# getentropy succeeds with non-OS fallback entropy

## Classification

High severity `security_control_failure`.

## Affected Locations

`arc4random/getentropy_aix.c:113`

## Summary

`getentropy()` is a cryptographic entropy provider, but on AIX it failed open when `/dev/urandom` could not be opened or read. Instead of returning failure, it called `getentropy_fallback()`, which hashes timing, process, address, filesystem, file-descriptor, and perfstat metadata, then returns success. Callers therefore received non-OS fallback bytes as cryptographic entropy with a successful `getentropy()` return value.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- `len <= 256`
- `/dev/urandom` open or validation/read fails, for example due to fd exhaustion or a missing device in a chroot

## Proof

When `getentropy_urandom(buf, len, "/dev/urandom", 0)` fails, it sets `errno = EIO` and returns `-1`.

The failure path in `getentropy()` did not fail closed. The `FAIL_INSTEAD_OF_TRYING_FALLBACK` branch was forcibly disabled with `#undef`, after which `getentropy()` called `getentropy_fallback(buf, len)`.

`getentropy_fallback()` hashes clocks, perfstat counters, process identifiers, addresses, filesystem metadata, and fd metadata. It then copies the SHA-512 digest into the caller buffer, restores the previous `errno`, and returns `0`.

Therefore, with `/dev/urandom` unavailable and `len <= 256`, `getentropy()` returned success even though the bytes did not come from an operating-system entropy source.

## Why This Is A Real Bug

`getentropy()` is expected to provide cryptographic entropy or fail. Returning success after synthesizing bytes from low-grade and partially predictable system metadata violates that contract.

This is security-relevant because callers trust a successful `getentropy()` result as suitable for cryptographic seeding. Under resource exhaustion or constrained runtime environments, the implementation silently downgraded entropy quality instead of reporting failure.

## Fix Requirement

If `/dev/urandom` fails, `getentropy()` must fail closed by setting `errno = EIO` and returning `-1`. It must not return success from a non-OS fallback entropy path.

## Patch Rationale

The patch removes the disabled `FAIL_INSTEAD_OF_TRYING_FALLBACK` block and removes the call to `getentropy_fallback()` from the `getentropy()` failure path.

After the patch, failure to obtain entropy from `/dev/urandom` deterministically sets `errno = EIO` and returns `-1`, preserving the cryptographic entropy provider contract.

## Residual Risk

None

## Patch

```diff
diff --git a/arc4random/getentropy_aix.c b/arc4random/getentropy_aix.c
index 9d085cf..efb5f1d 100644
--- a/arc4random/getentropy_aix.c
+++ b/arc4random/getentropy_aix.c
@@ -105,16 +105,8 @@ getentropy(void *buf, size_t len)
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