# BSD Extended Archive Name Overreads Backing Buffer

## Classification

Out-of-bounds read, medium severity.

## Affected Locations

- `libelf/libelf_ar_util.c:176`
- Function: `_libelf_ar_get_translated_name()`
- Affected path: BSD extended archive member names matching `#1/[0-9]+`

## Summary

`_libelf_ar_get_translated_name()` parsed the BSD extended archive name length from attacker-controlled archive header bytes, then copied that many bytes from immediately after the archive header without first checking that the bytes were still inside the mapped archive buffer.

A crafted archive with `#1/<large length>` near the end of `ar->e_rawfile` caused `strncpy()` to read beyond `ar->e_rawfile + ar->e_rawsize`. The copied bytes were returned as `Elf_Arhdr.ar_name`, allowing adjacent process memory disclosure or a crash if the overread reached unreadable memory.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Caller opens a crafted `ar` archive.
- Caller requests the translated archive member name, e.g. through `elf_getarhdr()`.
- Archive member uses BSD extended name syntax `#1/[0-9]+`.
- Declared BSD extended name length exceeds the remaining bytes in the mapped archive buffer.

## Proof

The reproduced path is:

- `elf_getarhdr()` calls `_libelf_ar_gethdr()` in `libelf/elf_getarhdr.c:44`.
- `_libelf_ar_gethdr()` calls `_libelf_ar_get_translated_name()` before any later member size adjustment in `libelf/libelf_ar.c:148`.
- `_libelf_ar_get_translated_name()` recognizes BSD extended names through `IS_EXTENDED_BSD_NAME(buf)`.
- It parses attacker-controlled `len` from `arh->ar_name`.
- It sets `q = (const unsigned char *)(arh + 1)`.
- It copies `len` bytes from `q` with `strncpy(s, (const char *) q, len)` without validating that `q + len` is within `ar->e_rawfile + ar->e_rawsize`.

A source-equivalent PoC with a logical archive size ending immediately after the header and a BSD name field of `#1/20` caused `elf_getarhdr()` to return `LEAKED_SECRET_BYTES!` from bytes placed just past the declared archive buffer.

## Why This Is A Real Bug

The vulnerable length is fully controlled by the archive file. The function already asserts only that `arh` itself lies inside the archive buffer; it did not assert or validate that the BSD extended name payload following the header is present.

Because the copied bytes are returned as the archive member name, the overread is externally observable by consumers that print, log, or otherwise expose archive member names. If the out-of-bounds range crosses into unmapped memory, the same bug can produce an attacker-controlled denial of service.

## Fix Requirement

Reject BSD extended names whose declared name length exceeds the remaining bytes in the backing archive buffer before allocating and copying the name.

## Patch Rationale

The patch computes:

- `q` as the first byte after the archive header.
- `r` as the archive buffer end: `ar->e_rawfile + ar->e_rawsize`.
- The remaining valid byte count as `(size_t)(r - q)` after ensuring `q <= r`.

It then rejects the archive with `LIBELF_SET_ERROR(ARCHIVE, 0)` if:

- `q > r`, meaning the computed name start is outside the backing buffer.
- `len > (size_t)(r - q)`, meaning the declared BSD extended name length would read past the archive end.

This places the boundary check before allocation and before `strncpy()`, preventing both disclosure and crash through this path.

## Residual Risk

None

## Patch

```diff
diff --git a/libelf/libelf_ar_util.c b/libelf/libelf_ar_util.c
index 83ff9cc..c054509 100644
--- a/libelf/libelf_ar_util.c
+++ b/libelf/libelf_ar_util.c
@@ -142,6 +142,16 @@ _libelf_ar_get_translated_name(const struct ar_hdr *arh, Elf *ar)
 			return (NULL);
 		}
 
+		/*
+		 * The file name follows the archive header.
+		 */
+		q = (const unsigned char *) (arh + 1);
+		r = ar->e_rawfile + ar->e_rawsize;
+		if (q > r || len > (size_t) (r - q)) {
+			LIBELF_SET_ERROR(ARCHIVE, 0);
+			return (NULL);
+		}
+
 		/*
 		 * Allocate space for the file name plus a
 		 * trailing NUL.
@@ -151,11 +161,6 @@ _libelf_ar_get_translated_name(const struct ar_hdr *arh, Elf *ar)
 			return (NULL);
 		}
 
-		/*
-		 * The file name follows the archive header.
-		 */
-		q = (const unsigned char *) (arh + 1);
-
 		(void) strncpy(s, (const char *) q, len);
 		s[len] = '\0';
```