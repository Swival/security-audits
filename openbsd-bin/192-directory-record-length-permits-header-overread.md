# Directory Record Length Permits Header Overread

## Classification

Out-of-bounds read, medium severity, confirmed with certainty.

## Affected Locations

`sbin/ncheck_ffs/ncheck_ffs.c:430`

`sbin/ncheck_ffs/ncheck_ffs.c:432`

`sbin/ncheck_ffs/ncheck_ffs.c:437`

## Summary

`ncheck_ffs` parses directory records from an attacker-controlled FFS image and advances through the directory block using `d_reclen`. The original loop only rejected zero-length records. A crafted nonzero `d_reclen` can advance `loc` near the end of the allocated directory buffer, leaving fewer bytes than a valid `struct direct` header for the next iteration. The next loop iteration then dereferences `dp->d_reclen`, and variants can reach `dp->d_ino` or `dp->d_name`, past the heap allocation.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Verified by reproduction and patched in `192-directory-record-length-permits-header-overread.patch`.

## Preconditions

`ncheck_ffs` is run on an attacker-controlled FFS image.

## Proof

A crafted directory inode can set the directory size to a full filesystem block so `searchdir()` receives `size == sblock->fs_bsize`.

The crafted directory block places a first record with:

- `d_ino == 0`
- nonzero `d_reclen`
- `d_reclen == fs_bsize - 1`

Execution then proceeds as follows:

- `searchdir()` allocates `dblk` with `malloc(sblock->fs_bsize)`.
- `bread()` fills `dblk` with attacker-controlled directory data.
- The loop condition `loc < size` is true at `loc == 0`.
- The code casts `dblk + loc` to `struct direct *`.
- The original check rejects only `dp->d_reclen == 0`.
- `loc += dp->d_reclen` advances `loc` to the final byte of the heap allocation.
- The next loop iteration still satisfies `loc < size`.
- `dp = (struct direct *)(dblk + loc)` points at a one-byte tail, not a complete directory entry header.
- Reading `dp->d_reclen` reads past the heap object.

Variants with a partial in-bounds header can also reach later reads of `dp->d_ino` and `dp->d_name[0]` beyond the valid directory bytes.

## Why This Is A Real Bug

The directory contents and `d_reclen` are attacker-controlled through the filesystem image. The loop treats `d_reclen` as trusted after checking only for zero. Nonzero short or oversized record lengths can leave `loc` inside `size` while the remaining bytes are insufficient for the next directory entry header.

Because the code dereferences fields of `struct direct` before validating that enough bytes remain for that structure and before validating that `d_reclen` fits within the remaining block, the parser performs heap out-of-bounds reads. This is undefined behavior and can cause practical process denial of service when parsing a malicious image.

## Fix Requirement

Before dereferencing or consuming a directory entry, `searchdir()` must verify that:

- the remaining bytes cover the fixed directory entry header;
- `d_reclen` is nonzero;
- `d_reclen` does not exceed the remaining bytes;
- `d_reclen` is large enough for the directory entry as described by the record contents.

## Patch Rationale

The patch adds validation at the top of the directory parsing loop:

```c
if (size - loc < sizeof(*dp) - sizeof(dp->d_name) ||
    dp->d_reclen == 0 || dp->d_reclen > size - loc ||
    dp->d_reclen < DIRSIZ(dp)) {
	warnx("corrupted directory, inode %llu",
	    (unsigned long long)ino);
	break;
}
```

This prevents the reproduced overread by stopping before parsing a record when fewer bytes remain than the fixed `struct direct` header. It also rejects malformed records whose length is zero, extends past the remaining directory bytes, or is smaller than the minimum size required for the entry name.

The existing corruption warning and loop termination behavior are preserved.

## Residual Risk

None

## Patch

```diff
diff --git a/sbin/ncheck_ffs/ncheck_ffs.c b/sbin/ncheck_ffs/ncheck_ffs.c
index 285716a..2a1c309 100644
--- a/sbin/ncheck_ffs/ncheck_ffs.c
+++ b/sbin/ncheck_ffs/ncheck_ffs.c
@@ -429,7 +429,9 @@ searchdir(ufsino_t ino, daddr_t blkno, long size, off_t filesize,
 		size = filesize;
 	for (loc = 0; loc < size; ) {
 		dp = (struct direct *)(dblk + loc);
-		if (dp->d_reclen == 0) {
+		if (size - loc < sizeof(*dp) - sizeof(dp->d_name) ||
+		    dp->d_reclen == 0 || dp->d_reclen > size - loc ||
+		    dp->d_reclen < DIRSIZ(dp)) {
 			warnx("corrupted directory, inode %llu",
 			    (unsigned long long)ino);
 			break;
```