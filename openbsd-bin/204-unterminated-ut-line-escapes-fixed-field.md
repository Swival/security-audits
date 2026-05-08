# Unterminated ut_line Escapes Fixed Field

## Classification

Out-of-bounds write, medium severity.

## Affected Locations

`usr.bin/last/last.c:432`

## Summary

`last` trusted `struct utmp.ut_line` as a NUL-terminated string while parsing attacker-supplied wtmp records via `last -f`. Because `ut_line` is a fixed-width `UT_LINESIZE` field, a crafted record with no NUL byte and no digit in `ut_line` made `want()` scan past the field and then write `'\0'` outside it.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

Victim runs `last -f` on attacker-controlled wtmp data.

## Proof

`main()` accepts `-f` and assigns the attacker-controlled path to `file`. `wtmp()` opens that file, reads records into the global `buf`, and for records with `bp->ut_name[0]` calls `want(bp, YES)`.

In `want()`, non-`console` and non-`tty` `ut_line` values are stripped at the first digit:

```c
for (s = bp->ut_line;
     *s != '\0' && !isdigit((unsigned char)*s); s++)
        ;
*s = '\0';
```

`ut_line` is a fixed-size field from the file, not guaranteed to contain a NUL terminator. A crafted record with nonempty `ut_name`, `ut_line` not starting with `console` or `tty`, and no NUL byte or digit inside `ut_line` makes `s` advance beyond `ut_line`.

The reproducer used an OpenBSD-compatible `struct utmp` layout and a crafted wtmp chunk filled with non-NUL, non-digit bytes. Running `last -f bad.wtmp -n 1` under AddressSanitizer produced a `global-buffer-overflow` in `want()` at line `432`, reached from `wtmp()` at line `346`.

## Why This Is A Real Bug

The vulnerable read and write operate on data loaded directly from a file chosen with `last -f`. Fixed-width utmp fields are not required to be NUL-terminated. The loop lacks a `UT_LINESIZE` bound, so malformed input can drive `s` outside `bp->ut_line`; the subsequent `*s = '\0'` corrupts adjacent record memory or can continue scanning beyond the loaded buffer.

## Fix Requirement

Limit the scan to `UT_LINESIZE` bytes and only write a terminator when the scan stops inside the `ut_line` field.

## Patch Rationale

The patch introduces an `end` pointer at `bp->ut_line + UT_LINESIZE`, adds `s < end` to the loop condition, and guards the write with `if (s < end)`. This preserves the intended stripping behavior when a digit or NUL is found within the field and avoids both out-of-bounds reads and out-of-bounds writes when the fixed field is unterminated.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/last/last.c b/usr.bin/last/last.c
index 6839922..12fc4e3 100644
--- a/usr.bin/last/last.c
+++ b/usr.bin/last/last.c
@@ -427,11 +427,12 @@ want(struct utmp *bp, int check)
 		 */
 		if ((strncmp(bp->ut_line, "console", strlen("console")) != 0) &&
 		    (strncmp(bp->ut_line, "tty", strlen("tty")) != 0)) {
-			char *s;
+			char *s, *end = bp->ut_line + UT_LINESIZE;
 			for (s = bp->ut_line;
-			     *s != '\0' && !isdigit((unsigned char)*s); s++)
+			     s < end && *s != '\0' && !isdigit((unsigned char)*s); s++)
 				;
-			*s = '\0';
+			if (s < end)
+				*s = '\0';
 		}
 	}
```