# byte-counted capacity overflows wide stream buffer

## Classification

Out-of-bounds write, high severity. Confidence: certain.

## Affected Locations

`stdio/open_wmemstream.c:62`

## Summary

`open_wmemstream` stores `st->size` as a byte count during initialization, but the rest of `wmemstream_write` treats `st->size` as a `wchar_t` element count. This inflates the capacity check and allows writes past the allocated wide-character buffer when attacker-controlled multibyte data is written to the stream.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

## Preconditions

A service writes attacker-controlled multibyte or ASCII data to a `FILE *` created by `open_wmemstream`.

## Proof

- `open_wmemstream` initializes `st->size` as `BUFSIZ * sizeof(wchar_t)` but allocates only that many bytes with `calloc(1, st->size)`.
- `wmemstream_write` computes `end = st->pos + l` and compares `end` against `st->size`.
- Because `st->size` is inflated by `sizeof(wchar_t)`, a `BUFSIZ` or `BUFSIZ+1` ASCII write does not trigger reallocation.
- `mbsnrtowcs` writes to `st->string + st->pos`; ASCII input converts to one `wchar_t` per input byte.
- After `BUFSIZ` ASCII bytes, the allocation contains only `BUFSIZ` `wchar_t` slots, but the terminator write stores `L'\0'` at index `BUFSIZ`, one wide element past the allocation.
- With additional input, attacker-controlled converted wide characters can also be written out of bounds.

## Why This Is A Real Bug

The allocation and capacity units are inconsistent. The buffer is physically allocated as `BUFSIZ * sizeof(wchar_t)` bytes, which holds `BUFSIZ` wide characters, but `wmemstream_write` believes the capacity is `BUFSIZ * sizeof(wchar_t)` wide characters. This makes the reallocation guard accept writes that exceed the real heap allocation, producing heap corruption or a process crash.

## Fix Requirement

Store `st->size` as a count of allocated `wchar_t` elements and allocate memory by multiplying that count by `sizeof(wchar_t)`.

## Patch Rationale

The patch changes initialization to:

```c
st->size = BUFSIZ;
st->string = calloc(st->size, sizeof(wchar_t));
```

This makes `st->size` consistent with its documented meaning and with later code paths that compare positions, lengths, and reallocation sizes in `wchar_t` elements. The existing `recallocarray(..., sizeof(wchar_t))` growth logic then operates on the same unit throughout.

## Residual Risk

None

## Patch

```diff
diff --git a/stdio/open_wmemstream.c b/stdio/open_wmemstream.c
index fca0b71..42ec482 100644
--- a/stdio/open_wmemstream.c
+++ b/stdio/open_wmemstream.c
@@ -138,8 +138,8 @@ open_wmemstream(wchar_t **pbuf, size_t *psize)
 		return (NULL);
 	}
 
-	st->size = BUFSIZ * sizeof(wchar_t);
-	if ((st->string = calloc(1, st->size)) == NULL) {
+	st->size = BUFSIZ;
+	if ((st->string = calloc(st->size, sizeof(wchar_t))) == NULL) {
 		free(st);
 		fp->_flags = 0;
 		return (NULL);
```