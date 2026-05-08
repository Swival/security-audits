# Out-of-Range Directory Inode Null Dereference

## Classification

Denial of service, medium severity, certain confidence.

## Affected Locations

`sbin/ncheck_ffs/ncheck_ffs.c:376`

## Summary

`ncheck_ffs` trusts inode numbers stored in directory entries while scanning an FFS image. A crafted directory entry can set `d_ino` outside the filesystem inode range. `searchdir()` passes that value to `getino()`, which returns `NULL` for out-of-range inode numbers, and the original code immediately dereferences it through `DIP(di, di_mode)`. This crashes `ncheck_ffs` while parsing attacker-controlled filesystem data.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

The victim runs `ncheck_ffs` on a crafted FFS image supplied or influenced by an attacker.

## Proof

The reproduced path is:

- `main()` scans the root directory through `scanonedir(ROOTINO, "")`.
- `scanonedir()` reads cached directory inode block pointers and calls `searchdir()` for directory data blocks.
- `searchdir()` reads attacker-controlled directory data into `dblk` and treats entries as `struct direct`.
- It skips only `d_ino == 0` and selected dot entries before calling `getino(dp->d_ino)`.
- `getino()` returns `NULL` when `inum < ROOTINO` or `inum >= sblock->fs_ncg * sblock->fs_ipg`.
- The original `searchdir()` immediately evaluates `DIP(di, di_mode)` with no `di` check.
- An out-of-range `d_ino` therefore causes a NULL pointer dereference and process termination.

## Why This Is A Real Bug

Directory entry inode numbers are read from the filesystem image and are attacker-controlled in the crafted-image threat model. The code already defines invalid inode numbers as non-resolvable by returning `NULL` from `getino()`, but the caller failed to handle that documented failure path. The dereference occurs before any later logic can reject or ignore the malformed directory entry, so the crash is directly reachable.

## Fix Requirement

`searchdir()` must validate the result of `getino(dp->d_ino)` before using `DIP()` or any inode fields. Invalid directory entries should be skipped.

## Patch Rationale

The patch adds a NULL check immediately after `getino(dp->d_ino)`:

```c
di = getino(dp->d_ino);
if (di == NULL)
	continue;
mode = DIP(di, di_mode) & IFMT;
```

This preserves existing behavior for valid inode numbers and treats out-of-range directory entries like other ignored invalid entries. It prevents the NULL dereference before all subsequent uses of `di`, including mode checks and verbose output.

## Residual Risk

None

## Patch

```diff
diff --git a/sbin/ncheck_ffs/ncheck_ffs.c b/sbin/ncheck_ffs/ncheck_ffs.c
index 285716a..bffdcb3 100644
--- a/sbin/ncheck_ffs/ncheck_ffs.c
+++ b/sbin/ncheck_ffs/ncheck_ffs.c
@@ -443,6 +443,8 @@ searchdir(ufsino_t ino, daddr_t blkno, long size, off_t filesize,
 				continue;
 		}
 		di = getino(dp->d_ino);
+		if (di == NULL)
+			continue;
 		mode = DIP(di, di_mode) & IFMT;
 		subino = dp->d_ino;
 		if (bsearch(&subino, ilist, ninodes, sizeof(*ilist), matchino)) {
```