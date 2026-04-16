# Insecure `vsprintf` fallback overflows `gzprintf` buffer

## Classification
- Type: vulnerability
- Severity: high
- Confidence: certain

## Affected Locations
- `gzwrite.c:396`

## Summary
When built with `ZLIB_INSECURE` and without `vsnprintf`, `gzvprintf()` falls back to `vsprintf(next, format, va)` while only provisioning a fixed internal buffer of `state->size` bytes. `vsprintf` performs no bounds checking, so oversized formatted output written through `gzprintf()` overruns the heap buffer before any truncation check can occur.

## Provenance
- Verified from the provided reproducer and source analysis
- Reproduced against the committed sources with AddressSanitizer
- Scanner reference: https://swival.dev

## Preconditions
- Built with `ZLIB_INSECURE`
- Built without `vsnprintf` support (`NO_vsnprintf`)
- Caller passes formatted output larger than `state->size - 1` to `gzprintf()`

## Proof
- `gz_init()` allocates `state->in` as `state->want << 1`, and `gzvprintf()` writes formatted output into the first half using `next`.
- `gzvprintf()` only reserves `state->size` bytes by setting `next[state->size - 1] = 0`, but under `NO_vsnprintf` with `ZLIB_INSECURE` it calls unbounded `vsprintf(next, format, va)` at `gzwrite.c:396`.
- That write can exceed `state->size - 1`, corrupting heap memory before the function inspects the terminator or returns failure.
- Reproduction used a small program compiled with `-DNO_vsnprintf -DZLIB_INSECURE -fsanitize=address`; calling `gzprintf(f, "%s", s)` with a 40,000-byte string triggered an ASan heap-buffer-overflow in `gzvprintf`, overrunning the 16,384-byte allocation made from `gz_init()`.

## Why This Is A Real Bug
The vulnerable path is reachable in supported build configurations explicitly enabled by `ZLIB_INSECURE`. The only guard in `gzvprintf()` is a post-write truncation check, which cannot prevent corruption because the overflow already occurred during `vsprintf`. This yields attacker-controlled heap memory corruption through `gzprintf()` arguments and is therefore a concrete memory-safety vulnerability, not a theoretical misuse.

## Fix Requirement
Remove the unbounded `vsprintf` fallback. If bounded `vsnprintf` is unavailable, fail safely by returning `Z_STREAM_ERROR` instead of attempting formatted output.

## Patch Rationale
The patch in `020-insecure-fallback-overflows-gzprintf-buffer.patch` disables the insecure `vsprintf` path and requires a bounded formatting primitive. This converts a heap overwrite into a clean error on unsupported builds, preserving safety without changing correct behavior on platforms that provide `vsnprintf`.

## Residual Risk
None

## Patch
```diff
--- a/gzwrite.c
+++ b/gzwrite.c
@@
-#ifdef NO_vsnprintf
-#  ifdef HAS_vsprintf_void
-    (void)vsprintf(next, format, va);
-    len = strlen(next);
-#  else
-    len = vsprintf(next, format, va);
-#  endif
-#else
+#ifdef NO_vsnprintf
+    return Z_STREAM_ERROR;
+#else
 #  ifdef HAS_vsnprintf_void
     (void)vsnprintf(next, state->size, format, va);
     len = strlen(next);
```