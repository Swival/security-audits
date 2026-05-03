# Compressed Chunk Overruns Piglet Bounce Area

## Classification

Out-of-bounds write. Severity: high. Confidence: certain.

## Affected Locations

`kern/subr_hibernate.c:935`

Primary vulnerable path also includes:

- `kern/subr_hibernate.c:1318`
- `kern/subr_hibernate.c:1338`
- `kern/subr_hibernate.c:1838`
- `kern/subr_hibernate.c:1866`

## Summary

A hibernation image read from attacker-controlled swap can set a chunk table entry with `compressed_size` larger than the fixed piglet bounce area. During resume, the kernel copies that many attacker-controlled bytes into `pva + 2 * HIBERNATE_CHUNK_SIZE` without checking that the destination fits inside the piglet.

The piglet is `4 * HIBERNATE_CHUNK_SIZE`; the bounce area begins at `2 * HIBERNATE_CHUNK_SIZE`, leaving only `2 * HIBERNATE_CHUNK_SIZE` bytes. Any larger `compressed_size` causes a kernel out-of-bounds write during resume.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched from the provided source and reproducer evidence.

## Preconditions

- System resumes from a hibernation image.
- Swap or the swap disk backend is attacker-controlled.
- The attacker preserves a valid hibernate signature and supplies a malicious chunk table.
- A chunk table entry contains `compressed_size > 2 * HIBERNATE_CHUNK_SIZE`.

## Proof

During resume, `hibernate_resume()` reads `disk_hib` from swap and then calls `hibernate_read_image()`.

`hibernate_read_image()` reads the chunk table from swap into the piglet-backed chunk table area. It then sums `chunks[i].compressed_size` using the attacker-controlled values from disk.

During unpack, `hibernate_unpack_image()` iterates over `local_hib->chunk_ctr` and calls:

```c
hibernate_process_chunk(local_hib, &chunks[fchunks[i]], image_cur);
```

`hibernate_process_chunk()` then passes the unvalidated on-disk chunk size to the piglet copy routine:

```c
hibernate_copy_chunk_to_piglet(img_cur,
 (vaddr_t)(pva + (HIBERNATE_CHUNK_SIZE * 2)), chunk->compressed_size);
```

The destination is the piglet bounce area beginning at:

```c
pva + 2 * HIBERNATE_CHUNK_SIZE
```

The piglet allocation is only:

```c
HIBERNATE_CHUNK_SIZE * 4
```

so the bounce area has capacity:

```c
2 * HIBERNATE_CHUNK_SIZE
```

`hibernate_copy_chunk_to_piglet()` copies page-by-page until `src < size + img_cur` and performs no destination bound check.

A malicious chunk table entry such as:

```c
compressed_size = 0x801000
```

on amd64/i386, where `HIBERNATE_CHUNK_SIZE` is `0x400000`, makes the kernel copy 4 KiB past the fixed 8 MiB bounce area.

## Why This Is A Real Bug

The size is attacker-controlled through the hibernation chunk table stored on swap. The kernel trusts this value after only validating the hibernate signature and machine compatibility. The signature does not constrain each chunk’s `compressed_size`.

The destination buffer is fixed-size by design. The source length is variable and disk-derived. Because `hibernate_copy_chunk_to_piglet()` has no destination capacity argument or bound check, oversized compressed chunks deterministically write past the piglet bounce area during resume.

This is concrete kernel memory corruption and can cause denial of service. Depending on adjacent physical memory layout, attacker-controlled image bytes may corrupt sensitive kernel memory.

## Fix Requirement

Reject any chunk whose `compressed_size` exceeds the bounce area capacity before copying it into the piglet.

The required bound is:

```c
chunk->compressed_size <= HIBERNATE_CHUNK_SIZE * 2
```

## Patch Rationale

The patch adds the missing validation at the narrowest unsafe point: immediately before `hibernate_process_chunk()` copies the compressed chunk into the piglet bounce area.

This protects the copy regardless of where the malicious size originated and prevents `hibernate_copy_chunk_to_piglet()` from being called with a length larger than the fixed destination.

A panic is appropriate in this path because unpack is already in the resume-time critical section where normal recovery and diagnostics are limited, and the existing code uses panic for invalid hibernation stream conditions.

## Residual Risk

None

## Patch

```diff
diff --git a/kern/subr_hibernate.c b/kern/subr_hibernate.c
index a21c330..df5e09d 100644
--- a/kern/subr_hibernate.c
+++ b/kern/subr_hibernate.c
@@ -1335,6 +1335,9 @@ hibernate_process_chunk(union hibernate_info *hib,
 {
 	char *pva = (char *)hib->piglet_va;
 
+	if (chunk->compressed_size > HIBERNATE_CHUNK_SIZE * 2)
+		panic("hibernate compressed chunk too large");
+
 	hibernate_copy_chunk_to_piglet(img_cur,
 	 (vaddr_t)(pva + (HIBERNATE_CHUNK_SIZE * 2)), chunk->compressed_size);
 	hibernate_inflate_region(hib, chunk->base,
```