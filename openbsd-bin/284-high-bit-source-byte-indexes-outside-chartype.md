# High-Bit Source Byte Indexes Outside Chartype

## Classification

Out-of-bounds read, medium severity.

## Affected Locations

`usr.bin/indent/lexi.c:144`

## Summary

`indent` token classification indexed the 128-byte `chartype` table with an attacker-controlled source byte before constraining it to the table range. Non-ASCII bytes at token start can therefore read before or after `chartype`, depending on platform `char` signedness.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

An attacker controls or supplies a source file processed by `indent`, and that file contains a high-bit non-ASCII byte at the next token start.

## Proof

`lexi()` skips only spaces and tabs before token classification. A high-bit byte at `buf_ptr` therefore reaches the classifier unchanged.

`chartype` is declared with exactly 128 entries in `usr.bin/indent/lexi.c`, but the classifier used:

```c
chartype[(int)*buf_ptr]
```

before any unsigned cast or bounds check.

A source file beginning with `0xff` triggers `chartype[-1]` on a signed-char build. A byte such as `0x80` similarly triggers a negative index on signed-char platforms, while unsigned-char platforms can index above 127.

ASan/UBSan reproduction on the committed `indent` sources with a file containing a single high-bit byte reported:

```text
usr.bin/indent/lexi.c:142:9: runtime error: index -1 out of bounds for type 'char[128]'
ERROR: AddressSanitizer: global-buffer-overflow
READ of size 1
#0 in lexi lexi.c:142
#1 in main indent.c:401
```

## Why This Is A Real Bug

The input byte is attacker-controlled, propagates directly into global `buf_ptr`, and is used as an array index into `chartype` without validating that it is in `[0, 127]`.

This is undefined behavior and a concrete out-of-bounds read of global storage. The sanitizer trace confirms the invalid read occurs during normal token classification before token handling continues.

## Fix Requirement

Cast source bytes to `unsigned char` before classification and ensure values are within the 128-byte `chartype` table before indexing. Bytes outside the table range must not be used as `chartype` indexes.

## Patch Rationale

The patch gates both `chartype` lookups in `lexi()` with:

```c
(unsigned char)*buf_ptr < sizeof(chartype)
```

and then indexes with:

```c
chartype[(unsigned char)*buf_ptr]
```

This prevents negative indexes on signed-char platforms and prevents indexes above 127 on unsigned-char platforms. High-bit bytes no longer enter the alphanumeric-token path through an invalid table read; they fall through to existing non-alphanumeric token handling.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/indent/lexi.c b/usr.bin/indent/lexi.c
index 19b1105..f62ad58 100644
--- a/usr.bin/indent/lexi.c
+++ b/usr.bin/indent/lexi.c
@@ -139,7 +139,8 @@ lexi(void)
     }
 
     /* Scan an alphanumeric token */
-    if (chartype[(int)*buf_ptr] == alphanum ||
+    if (((unsigned char)*buf_ptr < sizeof(chartype) &&
+	chartype[(unsigned char)*buf_ptr] == alphanum) ||
 	(buf_ptr[0] == '.' && isdigit((unsigned char)buf_ptr[1]))) {
 	/*
 	 * we have a character or number
@@ -210,7 +211,8 @@ lexi(void)
 	    }
 	}
 	else
-	    while (chartype[(int)*buf_ptr] == alphanum) {	/* copy it over */
+	    while ((unsigned char)*buf_ptr < sizeof(chartype) &&
+		chartype[(unsigned char)*buf_ptr] == alphanum) {	/* copy it over */
 		CHECK_SIZE_TOKEN;
 		*e_token++ = *buf_ptr++;
 		if (buf_ptr >= buf_end)
```