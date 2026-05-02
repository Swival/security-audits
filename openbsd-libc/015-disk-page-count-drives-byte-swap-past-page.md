# Disk Page Count Drives Byte-Swap Past Page

## Classification

High severity out-of-bounds write.

## Affected Locations

`db/hash/hash_page.c:574`

## Summary

When reading an attacker-controlled opposite-endian hash database page, `__get_page` trusts the on-disk 16-bit page entry count. After byte-swapping `bp[0]`, it computes `max = bp[0] + 2` and swaps `bp[1]` through `bp[max]` without verifying that `max` fits inside the allocated page buffer.

A crafted disk page can set `bp[0]` so the swapped count is very large, causing `M_16_SWAP(bp[i])` to write beyond the `hashp->BSIZE` page buffer.

## Provenance

Verified from supplied source, reproduced by analysis, and patched.

Scanner provenance: [Swival Security Scanner](https://swival.dev)

Confidence: certain.

## Preconditions

- Victim opens an attacker-controlled hash database file.
- The database file uses the opposite byte order from the victim host.
- The crafted page is a non-bitmap disk page.
- The crafted first 16-bit word swaps to a value exceeding the page's 16-bit entry capacity.

## Proof

`__get_buf` allocates a page buffer of exactly `hashp->BSIZE` bytes in `db/hash/hash_buf.c:193`.

`__get_page` reads one full disk page into that buffer in `db/hash/hash_page.c:527`.

For non-bitmap opposite-endian pages, `__get_page` performs:

```c
M_16_SWAP(bp[0]);
max = bp[0] + 2;
for (i = 1; i <= max; i++)
	M_16_SWAP(bp[i]);
```

Because `bp[0]` is attacker-controlled disk data and is not capped before use, a crafted value that swaps to `0xffff` makes `max` equal `65537`.

The loop then writes through `bp[65537]`, about 131 KB into memory, while the page buffer is only `hashp->BSIZE` bytes. Normal hash database page sizes are typically 4096 bytes and at most 65536 bytes, so the loop writes out of bounds.

## Why This Is A Real Bug

The vulnerable writes happen before any semantic validation of the page contents. The byte-swap macro writes back to `bp[i]`, so this is not only an out-of-bounds read; it corrupts memory past the heap page buffer.

The attacker controls the database file contents, including the first on-disk 16-bit word. Opening the crafted opposite-endian database is enough to reach the vulnerable swap path through normal hash page loading. The impact is attacker-triggered process memory corruption and practical denial of service, with possible stronger memory-safety impact depending on allocator layout.

## Fix Requirement

Validate the swapped page entry count before using it to drive indexed byte-swapping. The maximum index to be swapped must be strictly within the number of `u_int16_t` entries available in the `hashp->BSIZE` page buffer. Invalid pages must be rejected with an error.

## Patch Rationale

The patch adds a bounds check immediately after:

```c
M_16_SWAP(bp[0]);
max = bp[0] + 2;
```

and before the loop that writes `bp[1]` through `bp[max]`.

The check rejects pages where `max` would address beyond the allocated page:

```c
if (max >= hashp->BSIZE / sizeof(u_int16_t)) {
	errno = EFTYPE;
	return (-1);
}
```

This preserves valid opposite-endian page handling while preventing attacker-controlled counts from driving the swap loop outside the page buffer.

## Residual Risk

None

## Patch

```diff
diff --git a/db/hash/hash_page.c b/db/hash/hash_page.c
index 8e273db..4c28e9a 100644
--- a/db/hash/hash_page.c
+++ b/db/hash/hash_page.c
@@ -547,6 +547,10 @@ __get_page(HTAB *hashp, char *p, u_int32_t bucket, int is_bucket, int is_disk,
 			} else {
 				M_16_SWAP(bp[0]);
 				max = bp[0] + 2;
+				if (max >= hashp->BSIZE / sizeof(u_int16_t)) {
+					errno = EFTYPE;
+					return (-1);
+				}
 				for (i = 1; i <= max; i++)
 					M_16_SWAP(bp[i]);
 			}
```