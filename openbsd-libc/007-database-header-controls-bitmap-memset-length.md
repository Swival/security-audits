# Database Header Controls Bitmap Memset Length

## Classification

High severity out-of-bounds write.

Confidence: certain.

## Affected Locations

`db/hash/hash.c:172`

## Summary

Opening an attacker-supplied existing hash database can corrupt heap memory because `__hash_open` trusts bitmap metadata from the on-disk header. The computed bitmap page count `bpages` is used as the byte count multiplier for `memset(&hashp->mapp[0], 0, bpages * sizeof(u_int32_t *))`, but `hashp->mapp` is a fixed `NCACHED`-entry array. A header that makes `bpages > NCACHED` writes past the embedded array during database open.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

Victim opens an attacker-supplied existing `DB_HASH` database file.

## Proof

`__hash_open` reads the on-disk `HASHHDR` into `hashp->hdr`, byte-swaps it, and verifies only:

- `MAGIC`
- `VERSION`
- `H_CHARKEY`

It then computes:

```c
bpages = (hashp->SPARES[hashp->OVFL_POINT] +
    (hashp->BSIZE << BYTE_SHIFT) - 1) >>
    (hashp->BSHIFT + BYTE_SHIFT);
```

Before the patch, `bpages` was assigned to `hashp->nmaps` and used directly here:

```c
(void)memset(&hashp->mapp[0], 0, bpages * sizeof(u_int32_t *));
```

A concrete ASan-confirmed trigger used a valid existing hash DB header with:

- `OVFL_POINT = 31`
- `BSIZE = 4096`
- `BSHIFT = 12`
- `SPARES[31] = 200 * 32768 - 1`

This makes `bpages = 200`. Since `hashp->mapp` has only `NCACHED` entries, where `NCACHED = 32`, opening the file reaches the `memset` and writes `1600` bytes from the start of the fixed bitmap pointer array.

ASan reported:

```text
ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 1600
#1 __hash_open hash.c:175
allocated by calloc in __hash_open hash.c:105
```

## Why This Is A Real Bug

The overflow occurs during normal open of an existing hash database, before later bitmap bounds checks can protect consumers. The attacker controls the database header fields used to derive `bpages`, and `memset` uses that value to clear a fixed-size array. The result is attacker-controlled-length heap corruption past `hashp->mapp`.

## Fix Requirement

Reject existing database headers where the computed bitmap page count is outside the capacity of `hashp->mapp` before assigning `hashp->nmaps` or calling `memset`.

## Patch Rationale

The patch computes `bpages` immediately after validating the basic header identity fields and before segment allocation. It rejects malformed headers when:

```c
bpages < 0 || bpages > NCACHED
```

This ensures `memset` can only clear within the fixed `NCACHED`-entry `mapp` array. Returning `EFTYPE` is appropriate because an oversized bitmap count indicates an invalid on-disk hash database header.

## Residual Risk

None

## Patch

```diff
diff --git a/db/hash/hash.c b/db/hash/hash.c
index 797a8d0..eaddaf8 100644
--- a/db/hash/hash.c
+++ b/db/hash/hash.c
@@ -153,6 +153,13 @@ __hash_open(const char *file, int fd, int flags, int mode,
 			RETURN_ERROR(EFTYPE, error1);
 		if (hashp->hash(CHARKEY, sizeof(CHARKEY)) != hashp->H_CHARKEY)
 			RETURN_ERROR(EFTYPE, error1);
+		/* Read in bitmaps */
+		bpages = (hashp->SPARES[hashp->OVFL_POINT] +
+		    (hashp->BSIZE << BYTE_SHIFT) - 1) >>
+		    (hashp->BSHIFT + BYTE_SHIFT);
+		if (bpages < 0 || bpages > NCACHED)
+			RETURN_ERROR(EFTYPE, error1);
+
 		/*
 		 * Figure out how many segments we need.  Max_Bucket is the
 		 * maximum bucket number, so the number of buckets is
@@ -166,10 +173,6 @@ __hash_open(const char *file, int fd, int flags, int mode,
 			 * and errno will have been set.
 			 */
 			return (NULL);
-		/* Read in bitmaps */
-		bpages = (hashp->SPARES[hashp->OVFL_POINT] +
-		    (hashp->BSIZE << BYTE_SHIFT) - 1) >>
-		    (hashp->BSHIFT + BYTE_SHIFT);
 
 		hashp->nmaps = bpages;
 		(void)memset(&hashp->mapp[0], 0, bpages * sizeof(u_int32_t *));
```