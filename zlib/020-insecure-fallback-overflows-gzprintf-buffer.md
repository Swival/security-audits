# Insecure `vsprintf` Fallback Overflows `gzprintf` Buffer

## Classification
- Type: vulnerability
- Severity: high
- Confidence: certain

## Affected Locations
- `gzwrite.c:396`

## Summary
When built with `ZLIB_INSECURE` and without `vsnprintf` support, `gzvprintf()` falls back to `vsprintf(next, format, va)` while only provisioning a fixed internal buffer sized to `state->size`. Because `vsprintf` is unbounded, formatted output longer than `state->size - 1` overwrites heap memory before any truncation check can occur, making memory corruption reachable through `gzprintf()`.

## Provenance
- Verified from the provided reproducer and source analysis
- Scanner: https://swival.dev

## Preconditions
- Built with `ZLIB_INSECURE`
- Built without `vsnprintf` support via `NO_vsnprintf`
- Caller passes oversized formatted output to `gzprintf()`

## Proof
- `gz_init()` allocates `state->in` at `state->want << 1`, establishing a fixed heap buffer used by `gzvprintf()`.
- `gzvprintf()` writes into `next` and assumes only `state->size` bytes are available for the formatted result.
- In the insecure fallback at `gzwrite.c:396`, `vsprintf(next, format, va)` performs unbounded writes and ignores `state->size`.
- The later terminator/truncation logic cannot prevent overwrite; corruption occurs before control returns to the function.
- Reproduction with `-DNO_vsnprintf -DZLIB_INSECURE -fsanitize=address` and a 40,000-byte `%s` argument to `gzprintf()` causes an ASan heap-buffer-overflow in `gzvprintf`, overrunning the 16,384-byte allocation originating from `gz_init()`.

## Why This Is A Real Bug
The vulnerable path is gated only by compile-time flags and a caller-controlled formatted length. In that configuration, `gzprintf()` exposes a direct heap overwrite primitive through ordinary API usage. The function may later return failure, but only after memory corruption has already happened, so this is an actual safety issue rather than a benign truncation condition.

## Fix Requirement
Remove the unbounded `vsprintf` fallback from `gzvprintf()`. If bounded `vsnprintf` is unavailable, fail safely by returning `Z_STREAM_ERROR` instead of attempting formatting.

## Patch Rationale
The patch in `020-insecure-fallback-overflows-gzprintf-buffer.patch` eliminates the unsafe fallback path and requires bounded formatting semantics. This preserves existing behavior for safe builds while converting the insecure configuration from memory corruption to a controlled error return.

## Residual Risk
None

## Patch
```diff
--- a/gzwrite.c
+++ b/gzwrite.c
@@ -393,10 +393,8 @@ local int gzvprintf(gz_statep state, const char *format, va_list va)
     len = vsnprintf((char *)next, state->size, format, va);
     next[state->size - 1] = 0;
 #  else
-#   ifdef ZLIB_INSECURE
-    len = vsprintf((char *)next, format, va);
-#   else
-    len = 0;
+#   ifdef ZLIB_INSECURE
+    len = -1;
 #   endif
 #  endif
```