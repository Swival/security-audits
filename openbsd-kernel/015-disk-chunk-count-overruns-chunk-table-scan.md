# disk chunk count overruns chunk table scan

## Classification

out-of-bounds read, medium severity, confidence certain

## Affected Locations

`kern/subr_hibernate.c:1718`

## Summary

`hibernate_read_image()` trusts the disk-persisted `hib->chunk_ctr` while scanning a fixed-size hibernate chunk table. The function allocates and maps exactly `HIBERNATE_CHUNK_TABLE_SIZE` bytes for `chunks`, reads exactly that table size from disk, then loops up to `hib->chunk_ctr` and reads `chunks[i].compressed_size`. An attacker-controlled oversized `chunk_ctr` can make the kernel read beyond the mapped chunk-table buffer during hibernate resume.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- The system attempts hibernate resume from attacker-controlled swap contents.
- The malicious swap contents contain an otherwise acceptable hibernate signature.
- The attacker controls the persisted `chunk_ctr` value in the hibernate signature.

## Proof

`hibernate_resume()` reads `disk_hib` from swap and validates the magic, kernel hash, range count, and memory ranges before passing `disk_hib` to `hibernate_read_image()`.

`hibernate_read_image()` then:

- Allocates exactly `HIBERNATE_CHUNK_TABLE_SIZE` bytes for the chunk table.
- Maps that fixed-size table buffer.
- Reads exactly `HIBERNATE_CHUNK_TABLE_SIZE` bytes from disk into it.
- Casts the buffer to `struct hibernate_disk_chunk *`.
- Iterates with `for (i = 0; i < hib->chunk_ctr; i++)`.
- Reads `chunks[i].compressed_size` without first checking that `i` remains within the table capacity.

Because `chunk_ctr` is disk-controlled and was not bounded, a value such as `0x100000` remains below `INT_MAX` but far exceeds `HIBERNATE_CHUNK_TABLE_SIZE / sizeof(*chunks)`, causing reads past the chunk-table mapping.

## Why This Is A Real Bug

The chunk table has a hard byte capacity, but the loop count comes from attacker-controlled disk state. The code reads only one table-sized buffer, so any `chunk_ctr` greater than the number of entries representable in that buffer makes `chunks[i]` address memory outside the allocation. This is a kernel memory-safety violation during resume and can practically produce a boot/resume denial of service through a fault, panic, or corrupted follow-on sizing.

## Fix Requirement

Reject any hibernate image whose persisted `chunk_ctr` exceeds the number of `struct hibernate_disk_chunk` entries that fit in `HIBERNATE_CHUNK_TABLE_SIZE`.

## Patch Rationale

The patch adds the missing capacity check immediately after `chunks` is derived from the fixed-size chunk-table buffer and before any scan using `hib->chunk_ctr`. This prevents the out-of-bounds read while preserving existing behavior for valid images.

## Residual Risk

None

## Patch

```diff
diff --git a/kern/subr_hibernate.c b/kern/subr_hibernate.c
index a21c330..24a47fa 100644
--- a/kern/subr_hibernate.c
+++ b/kern/subr_hibernate.c
@@ -1714,6 +1714,10 @@ hibernate_read_image(union hibernate_info *hib)
 	compressed_size = 0;
 
 	chunks = (struct hibernate_disk_chunk *)chunktable;
+	if (hib->chunk_ctr > HIBERNATE_CHUNK_TABLE_SIZE / sizeof(*chunks)) {
+		status = 1;
+		goto unmap;
+	}
 
 	for (i = 0; i < hib->chunk_ctr; i++)
 		compressed_size += chunks[i].compressed_size;
```