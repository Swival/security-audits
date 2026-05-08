# Unterminated Gzip Header Exhausts Verifier Memory

## Classification

Denial of service, medium severity, confirmed.

## Affected Locations

`usr.bin/signify/zsig.c:116`

## Summary

`readgz_header()` accepts gzip `FNAME` and `FCOMMENT` optional fields and scans for a terminating NUL. If the terminator is absent, it continues reading and doubles the buffer whenever full. Because no maximum optional-field/header length is enforced, an attacker-controlled signature stream can force unbounded memory allocation before signature verification rejects the input.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The verifier reads an attacker-controlled signature file or stdin.
- The attacker supplies a gzip header with `FNAME_FLAG` or `FCOMMENT_FLAG`.
- The selected optional field is not NUL-terminated before a large or endless byte stream.

## Proof

`zverify()` opens the supplied signature stream and calls `readgz_header()` before `verifyzdata()`.

In `readgz_header()`:

- The buffer starts at `sz = 1023`.
- When `len == sz`, the code doubles `sz` and calls `realloc()`.
- For `FNAME_FLAG`, it searches `buf + pos` with `memchr()` for `0`.
- For `FCOMMENT_FLAG`, it also searches with `memchr()` for `0`.
- If no NUL is found, the function continues reading instead of rejecting.
- Signature verification is not reached until after the gzip header is fully parsed.

A minimal malicious prefix is:

```text
1f 8b 08 10 00 00 00 00 00 03 41 41 41 ...
```

This is a gzip magic/header with `FCOMMENT_FLAG`, followed by non-NUL bytes. A pipe or very large malicious signature file can keep the comment unterminated and drive repeated reallocations until verifier memory is exhausted.

## Why This Is A Real Bug

The parser buffers the entire unterminated optional gzip field before it can reject the stream as truncated. EOF only catches finite malformed input after all available bytes have already been read into memory. For attacker-controlled stdin or a large sigfile, this creates attacker-controlled memory growth before any cryptographic signature validation occurs.

## Fix Requirement

Impose a maximum gzip header/comment length and reject inputs that exceed it before growing the allocation further.

## Patch Rationale

The patch adds `GZHEADERMAX` and enforces it in the buffer growth path. Once the buffered gzip header reaches the maximum size, `readgz_header()` exits with `gzheader too long` instead of doubling the allocation again. The growth logic also caps `sz` at `GZHEADERMAX`, preventing overshoot when the current allocation is below the limit.

This preserves normal gzip header parsing while bounding memory use for malformed or malicious unterminated optional fields.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/signify/zsig.c b/usr.bin/signify/zsig.c
index 507517e..5ef3ae9 100644
--- a/usr.bin/signify/zsig.c
+++ b/usr.bin/signify/zsig.c
@@ -47,6 +47,7 @@ struct gzheader {
 #define FCOMMENT_FLAG 16
 
 #define GZHEADERLENGTH 10
+#define GZHEADERMAX 65536LU
 #define MYBUFSIZE 65536LU
 
 
@@ -67,7 +68,11 @@ readgz_header(struct gzheader *h, int fd)
 
 	while (1) {
 		if (len == sz) {
+			if (sz >= GZHEADERMAX)
+				errx(1, "gzheader too long");
 			sz *= 2;
+			if (sz > GZHEADERMAX)
+				sz = GZHEADERMAX;
 			buf = realloc(buf, sz);
 			if (!buf)
 				err(1, "realloc");
```