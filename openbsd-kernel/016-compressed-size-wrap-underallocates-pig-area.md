# compressed size wrap underallocates pig area

## Classification

High severity out-of-bounds write.

## Affected Locations

`kern/subr_hibernate.c:1718`

`kern/subr_hibernate.c:1721`

`kern/subr_hibernate.c:1727`

`kern/subr_hibernate.c:1853`

`kern/subr_hibernate.c:1859`

`kern/subr_hibernate.c:1866`

## Summary

Resume trusts the on-disk hibernate chunk table after signature comparison. `hibernate_read_image()` sums disk-controlled `chunks[i].compressed_size` values without overflow checks, then computes `pig_sz = compressed_size + HIBERNATE_CHUNK_SIZE`. If either arithmetic operation wraps, the pig area allocation is smaller than the later read target. `hibernate_read_chunks()` still uses the unbounded chunk sizes and writes attacker-controlled disk bytes past the allocated pig area into unrelated physical memory.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Resume reads attacker-controlled hibernate signature and chunk table from swap.
- The malicious hibernate signature passes the existing magic and signature comparisons.
- A malicious swap disk backend can replay or forge the matching hibernate metadata.

## Proof

A malicious swap backend can provide a matching hibernate signature with `chunk_ctr = 1` and set:

```c
chunks[0].compressed_size = (size_t)-HIBERNATE_CHUNK_SIZE + PAGE_SIZE;
```

On amd64 this is `0xffffffffffc01000`.

Propagation:

- `hibernate_read_image()` sums the disk-controlled value into `compressed_size` at `kern/subr_hibernate.c:1718`.
- `disk_size` preserves that large value at `kern/subr_hibernate.c:1721`.
- `pig_sz = compressed_size + HIBERNATE_CHUNK_SIZE` wraps to one page at `kern/subr_hibernate.c:1727`.
- `uvm_pmr_alloc_pig()` allocates only the wrapped one-page pig area.
- `image_start = image_end - disk_size` points outside the one-page allocation.
- `hibernate_read_chunks()` maps pages at `img_cur` and reads attacker-controlled disk bytes into them at `kern/subr_hibernate.c:1853`, `kern/subr_hibernate.c:1859`, and `kern/subr_hibernate.c:1866`.

Impact: the first chunk read can write outside the pig area into unrelated physical memory, causing resume-time kernel memory corruption or denial of service.

## Why This Is A Real Bug

The chunk table is read from disk during resume and is attacker-controlled under the stated storage-backend threat model. The code validates the hibernate signature but does not validate arithmetic on `compressed_size`. The wrapped `pig_sz` controls allocation size, while the original disk-controlled chunk size controls the amount and destination progression of physical-memory writes. This creates a concrete allocation-size versus copy-size mismatch and an out-of-bounds physical memory write.

## Fix Requirement

Reject overflow during:

- Accumulation of total `compressed_size` from `chunks[i].compressed_size`.
- Addition of `HIBERNATE_CHUNK_SIZE` to compute `pig_sz`.

On overflow, abort image reading before allocating or reading chunk data.

## Patch Rationale

The patch adds explicit wrap checks in `hibernate_read_image()`:

- Before each accumulation, it checks whether `compressed_size + chunks[i].compressed_size` would be less than the current `compressed_size`.
- Before pig allocation, it checks whether `compressed_size + HIBERNATE_CHUNK_SIZE` wrapped below `compressed_size`.

Both failures set `status = 1` and jump to `unmap`, preserving the existing error path and avoiding any pig allocation or disk read based on wrapped sizes.

## Residual Risk

None

## Patch

```diff
diff --git a/kern/subr_hibernate.c b/kern/subr_hibernate.c
index a21c330..cd089a0 100644
--- a/kern/subr_hibernate.c
+++ b/kern/subr_hibernate.c
@@ -1715,8 +1715,13 @@ hibernate_read_image(union hibernate_info *hib)
 
 	chunks = (struct hibernate_disk_chunk *)chunktable;
 
-	for (i = 0; i < hib->chunk_ctr; i++)
+	for (i = 0; i < hib->chunk_ctr; i++) {
+		if (compressed_size + chunks[i].compressed_size < compressed_size) {
+			status = 1;
+			goto unmap;
+		}
 		compressed_size += chunks[i].compressed_size;
+	}
 
 	disk_size = compressed_size;
 
@@ -1725,6 +1730,10 @@ hibernate_read_image(union hibernate_info *hib)
 
 	/* Allocate the pig area */
 	pig_sz = compressed_size + HIBERNATE_CHUNK_SIZE;
+	if (pig_sz < compressed_size) {
+		status = 1;
+		goto unmap;
+	}
 	if (uvm_pmr_alloc_pig(&pig_start, pig_sz, hib->piglet_pa) == ENOMEM) {
 		status = 1;
 		goto unmap;
```