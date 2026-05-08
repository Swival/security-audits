# Exact-Size Expansion Writes Past Stack Buffer

## Classification

High severity out-of-bounds write.

## Affected Locations

`usr.bin/pkgconf/libpkgconf/tuple.c:417`

## Summary

`pkgconf_tuple_parse()` stores expanded tuple text in a fixed stack buffer, `char buf[PKGCONF_BUFSIZE]`. The plain-copy loop allowed writes until `bptr - buf < PKGCONF_BUFSIZE`, which permits `bptr` to advance to one byte past the last valid write position. The later unconditional `*bptr = '\0'` then writes the terminator out of bounds for an exact-size expansion.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Victim runs `pkgconf` on an attacker-controlled `.pc` file.
- The crafted `.pc` file supplies a variable value that reaches `pkgconf_tuple_parse()`.
- The expanded value reaches exactly `PKGCONF_BUFSIZE` bytes before NUL termination.

## Proof

A `.pc`-style assignment with `x=` followed by 65535 attacker-controlled bytes reaches tuple parsing through:

`pkgconf_pkg_parser_value_set()` -> `pkgconf_tuple_add(..., true)` -> `pkgconf_tuple_parse()`

The relevant parser state is:

- `pkgconf_tuple_parse()` declares `char buf[PKGCONF_BUFSIZE]`.
- The plain-copy path writes attacker bytes with `*bptr++ = *ptr`.
- The loop condition was `bptr - buf < PKGCONF_BUFSIZE`.
- After an exact-size copy, `bptr == buf + PKGCONF_BUFSIZE`.
- The unconditional terminator write `*bptr = '\0'` writes one byte past `buf`.

The reproducer confirmed this with ASan: a `.pc`-style line containing `x=` plus 65535 `A` bytes triggers `stack-buffer-overflow` on the terminator write in `pkgconf_tuple_parse()`.

The file reader does not prevent reachability because `pkgconf_fgetline()` / `pkgconf_buffer_push_byte()` use a dynamically growing buffer before tuple parsing.

## Why This Is A Real Bug

The stack buffer has valid indices `0` through `PKGCONF_BUFSIZE - 1`. The previous loop condition allowed the copy loop to consume all `PKGCONF_BUFSIZE` positions and leave no room for the required NUL terminator. Since the terminator write is unconditional, an exact-size attacker-controlled value reliably produces a one-byte stack out-of-bounds write.

This is not a theoretical parser edge case: attacker-controlled `.pc` variable assignments are parsed with expansion enabled and can reach the vulnerable function.

## Fix Requirement

Reserve one byte in `buf` for the NUL terminator during the copy loop.

## Patch Rationale

The patch changes the loop bound from:

```c
bptr - buf < PKGCONF_BUFSIZE
```

to:

```c
bptr - buf < PKGCONF_BUFSIZE - 1
```

This guarantees that `bptr` never advances beyond `buf + PKGCONF_BUFSIZE - 1` during plain copying, leaving the final byte available for the unconditional `'\0'` terminator.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/pkgconf/libpkgconf/tuple.c b/usr.bin/pkgconf/libpkgconf/tuple.c
index 83f6a47..035fa01 100644
--- a/usr.bin/pkgconf/libpkgconf/tuple.c
+++ b/usr.bin/pkgconf/libpkgconf/tuple.c
@@ -322,7 +322,7 @@ pkgconf_tuple_parse(const pkgconf_client_t *client, pkgconf_list_t *vars, const
 			bptr += pkgconf_strlcpy(buf, client->sysroot_dir, sizeof buf);
 	}
 
-	for (ptr = value; *ptr != '\0' && bptr - buf < PKGCONF_BUFSIZE; ptr++)
+	for (ptr = value; *ptr != '\0' && bptr - buf < PKGCONF_BUFSIZE - 1; ptr++)
 	{
 		if (*ptr != '$' || (*ptr == '$' && *(ptr + 1) != '{'))
 			*bptr++ = *ptr;
```