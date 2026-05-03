# Unbounded TXT_DB Line Growth Exhausts Memory

## Classification

Denial of service, medium severity, availability impact.

## Affected Locations

`txt_db/txt_db.c:97`

## Summary

`TXT_DB_read()` grows its reusable input buffer by `BUFSIZE` whenever a partial line does not end in `\n`. Before the patch, there was no TXT_DB line-length cap, so an attacker-controlled BIO that continuously supplied newline-free data could force repeated `BUF_MEM_grow_clean()` reallocations until allocator failure or process memory exhaustion.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

An application parses attacker-controlled input through `TXT_DB_read()` using a caller-supplied BIO.

## Proof

`TXT_DB_read()` initializes `size` to `BUFSIZE` and reads into `buf->data` with `BIO_gets()`.

If a read chunk does not contain a newline:

- `strlen(&(buf->data[offset]))` is added to `offset`.
- `buf->data[offset - 1] != '\n'` causes the loop to continue.
- On the next iteration, `offset != 0` causes `size += BUFSIZE`.
- `BUF_MEM_grow_clean(buf, size)` reallocates the buffer.
- No maximum line length or total input bound existed before growth.

A peer controlling a line-capable BIO can stream bytes without `\n`, causing unbounded line accumulation. The reproducer confirmed that remote input can reach this path through buffered BIO/socket BIO behavior and that growth only stops at allocator failure or the large `BUF_MEM_grow_clean()` limit.

## Why This Is A Real Bug

The vulnerable loop treats a newline-free stream as one incomplete TXT_DB line and preserves all accumulated bytes. Since the buffer grows before any parsing or release of the partial line, attacker-controlled input directly controls memory growth. The failure mode is not limited to a clean parser error; it can exhaust process memory and deny service to the application using this public parser API.

## Fix Requirement

Enforce a maximum TXT_DB line length before increasing the buffer for a continued partial line.

## Patch Rationale

The patch introduces `MAX_LINE_SIZE` and checks the pending growth before `size += BUFSIZE`.

```c
#define MAX_LINE_SIZE	(1024 * 1024)
```

```c
if (size > MAX_LINE_SIZE - BUFSIZE) {
	er = 2;
	goto err;
}
size += BUFSIZE;
```

This prevents newline-free input from driving unbounded reallocations while preserving existing parsing behavior for lines up to the configured limit. The check is performed before growth, so the buffer cannot exceed the cap through the continuation path.

## Residual Risk

None

## Patch

`042-unbounded-txt-db-line-growth-exhausts-memory.patch`

```diff
diff --git a/txt_db/txt_db.c b/txt_db/txt_db.c
index 7d1f82c..6f17683 100644
--- a/txt_db/txt_db.c
+++ b/txt_db/txt_db.c
@@ -65,6 +65,7 @@
 
 #undef BUFSIZE
 #define BUFSIZE	512
+#define MAX_LINE_SIZE	(1024 * 1024)
 
 TXT_DB *
 TXT_DB_read(BIO *in, int num)
@@ -106,6 +107,10 @@ TXT_DB_read(BIO *in, int num)
 	offset = 0;
 	for (;;) {
 		if (offset != 0) {
+			if (size > MAX_LINE_SIZE - BUFSIZE) {
+				er = 2;
+				goto err;
+			}
 			size += BUFSIZE;
 			if (!BUF_MEM_grow_clean(buf, size))
 				goto err;
```