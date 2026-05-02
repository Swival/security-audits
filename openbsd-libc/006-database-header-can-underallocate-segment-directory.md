# Database Header Can Underallocate Segment Directory

## Classification

Out-of-bounds write. Severity: high. Confidence: certain.

## Affected Locations

`db/hash/hash.c:160`

## Summary

Opening an attacker-supplied existing hash database can corrupt heap memory. The existing-file path trusts on-disk header fields, computes a required segment count from `MAX_BUCKET` and `SGSIZE`, then allocates the segment directory using the attacker-controlled `DSIZE`. If `DSIZE < nsegs`, initialization writes past the allocated directory.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

Victim opens an attacker-supplied existing hash database file.

## Proof

`__hash_open` reads the on-disk `HASHHDR` into `hashp->hdr`, byte-swaps it when needed, and accepts the header after checking only magic, version, and `H_CHARKEY`.

The code then computes:

```c
nsegs = (hashp->MAX_BUCKET + 1 + hashp->SGSIZE - 1) /
	 hashp->SGSIZE;
```

Those inputs are attacker-controlled header fields. `alloc_segs(hashp, nsegs)` allocates:

```c
hashp->dir = calloc(hashp->DSIZE, sizeof(SEGMENT *))
```

but later writes:

```c
for (i = 0; i < nsegs; i++)
	hashp->dir[i] = &store[i << hashp->SSHIFT];
```

A crafted valid-looking header with `DSIZE=1`, `SGSIZE=1`, `SSHIFT=0`, and `MAX_BUCKET=1` yields `nsegs=2`. The code allocates one directory slot, then writes `dir[0]` and `dir[1]`, causing a heap out-of-bounds write during database open.

## Why This Is A Real Bug

The vulnerable path is reachable before any trusted reconstruction of header invariants. The file format fields used for allocation and loop bounds are attacker-controlled in the existing-file path. The allocation size is derived from `DSIZE`, while the write count is derived from computed `nsegs`; no invariant enforces `nsegs <= DSIZE` before the loop. This creates deterministic heap memory corruption on open, with denial of service as the minimum impact.

## Fix Requirement

Reject existing database headers where the computed segment count exceeds the directory size before calling `alloc_segs`.

## Patch Rationale

The patch validates the required invariant at the point where `nsegs` is computed and before allocation occurs. Returning `EFTYPE` treats the malformed database as an invalid file type, matching nearby header validation failures. This prevents `alloc_segs` from allocating an undersized `hashp->dir` and eliminates the out-of-bounds write.

## Residual Risk

None

## Patch

```diff
diff --git a/db/hash/hash.c b/db/hash/hash.c
index 797a8d0..eef2344 100644
--- a/db/hash/hash.c
+++ b/db/hash/hash.c
@@ -160,6 +160,8 @@ __hash_open(const char *file, int fd, int flags, int mode,
 		 */
 		nsegs = (hashp->MAX_BUCKET + 1 + hashp->SGSIZE - 1) /
 			 hashp->SGSIZE;
+		if (nsegs > hashp->DSIZE)
+			RETURN_ERROR(EFTYPE, error1);
 		if (alloc_segs(hashp, nsegs))
 			/*
 			 * If alloc_segs fails, table will have been destroyed
```