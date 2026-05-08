# INT32_MIN Token Overflows Signed Negation

## Classification

Denial of service, medium severity.

## Affected Locations

`usr.bin/rsync/downloader.c:487`

## Summary

A malicious rsync sender can send a raw negative block token equal to `INT32_MIN`. The receiver treats negative values as block tokens and computes `tok = -rawtok - 1` before validating the token range. Negating `INT32_MIN` overflows signed `int32_t` arithmetic, triggering undefined behavior that can abort or miscompile the receiver process.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The receiver processes tokens from an attacker-controlled sender.
- The downloader is in `DOWNLOAD_READ_REMOTE`.
- Prior block metadata passes `blk_send_ack()` validation.

## Proof

The downloader reads the next token from the sender with `io_read_int()` in `rsync_downloader()`.

`io_read_int()` accepts raw 32-bit little-endian values without filtering, so the byte sequence for `0x80000000` is interpreted as `INT32_MIN`.

When `rawtok < 0`, the downloader enters the block-token branch and immediately computes:

```c
tok = -rawtok - 1;
```

For `rawtok == INT32_MIN`, the expression `-rawtok` cannot be represented in signed `int32_t`, so signed overflow occurs before the later bounds check against `p->blk.blksz`.

A minimal UBSan build of the same expression aborts with:

```text
runtime error: negation of -2147483648 cannot be represented
```

This confirms attacker-triggerable denial-of-service behavior on hardened or sanitized builds. The unpatched code has no guard before the negation.

## Why This Is A Real Bug

The token value is sender-controlled and reaches the vulnerable expression without validation. The later `tok >= p->blk.blksz` check does not mitigate the issue because undefined behavior occurs first. In C, signed overflow is undefined behavior, and hardened builds commonly terminate on this condition.

## Fix Requirement

Reject `rawtok == INT32_MIN` before performing signed negation, or convert through a safe unsigned/widened representation that cannot overflow.

## Patch Rationale

The patch adds an explicit guard in the negative-token branch:

```c
if (rawtok == INT32_MIN) {
	ERRX("%s: invalid token", p->fname);
	goto out;
}
```

This prevents the only signed `int32_t` value whose negation is not representable from reaching `tok = -rawtok - 1`. All other negative token values preserve existing behavior and continue to be range-checked against `p->blk.blksz`.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/rsync/downloader.c b/usr.bin/rsync/downloader.c
index cab6eb2..5401132 100644
--- a/usr.bin/rsync/downloader.c
+++ b/usr.bin/rsync/downloader.c
@@ -486,6 +486,10 @@ again:
 
 		return 1;
 	} else if (rawtok < 0) {
+		if (rawtok == INT32_MIN) {
+			ERRX("%s: invalid token", p->fname);
+			goto out;
+		}
 		tok = -rawtok - 1;
 		if (tok >= p->blk.blksz) {
 			ERRX("%s: token not in block set: %zu (have %zu blocks)",
```