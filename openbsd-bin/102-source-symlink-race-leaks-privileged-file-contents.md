# Source Symlink Race Leaks Privileged File Contents

## Classification

Medium severity information disclosure.

## Affected Locations

`bin/mv/mv.c:236`

`bin/mv/mv.c:279`

`bin/mv/mv.c:295`

`bin/mv/mv.c:289`

`bin/mv/mv.c:293`

`bin/mv/mv.c:344`

## Summary

A privileged cross-filesystem `mv` can disclose root-readable file contents when the source path is attacker-controlled. `do_move()` records source metadata with `lstat()` and decides to use `fastcopy()` when that metadata indicates a regular file. After `rename()` fails with `EXDEV`, `fastcopy()` reopens the source by pathname using `open(from, O_RDONLY)`. An attacker can replace the original source file with a symlink between the `lstat()` and `open()`, causing privileged `mv` to follow the symlink and copy the target file into an attacker-readable destination.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

A lower-privileged local attacker controls the source path or source directory.

A privileged `mv` operation moves that source across filesystems, causing `rename()` to fail with `EXDEV` and enter the copy/unlink fallback path.

The attacker can replace the source regular file with a symlink after `do_move()` performs `lstat()` and before `fastcopy()` opens the path.

## Proof

`do_move()` performs `lstat(from, &fsb)` and uses `fsb` to determine that the source is a regular file.

When `rename(from, to)` fails with `EXDEV`, `do_move()` calls:

```c
return (S_ISREG(fsb.st_mode) ?
    fastcopy(from, to, &fsb) : mvcopy(from, to));
```

`fastcopy()` then opens the source path independently:

```c
if ((from_fd = open(from, O_RDONLY)) == -1) {
```

This `open()` follows symlinks and is not tied to the inode previously observed by `lstat()`. If the attacker swaps `from` to a symlink after `lstat()`, the privileged process opens the symlink target.

The copy loop writes bytes from that opened file descriptor to the destination:

```c
while ((nread = read(from_fd, bp, blen)) > 0)
    if (write(to_fd, bp, nread) != nread) {
```

The destination metadata is restored from the original attacker-controlled source metadata through `fchown()` and `fchmod()`, making the leaked contents readable when the attacker selected accessible metadata and destination.

Finally, `unlink(from)` removes only the swapped source path after the copy has completed. It does not prevent or undo the disclosure.

## Why This Is A Real Bug

This is a classic time-of-check/time-of-use race. The security-relevant decision is made from `lstat()` metadata, but the copied object is selected later by a pathname `open()` that can resolve to a different file. Because the operation can run with elevated privileges, the opened symlink target can be readable to the privileged process but not to the attacker. The fallback copy then materializes those privileged-only contents at the attacker-chosen destination.

## Fix Requirement

The source object copied by `fastcopy()` must be the same regular file observed by `do_move()`.

The implementation must avoid following a replacement symlink and must verify that the opened file descriptor matches the earlier metadata before copying.

## Patch Rationale

The patch opens the source with:

```c
open(from, O_RDONLY | O_NONBLOCK | O_NOFOLLOW)
```

`O_NOFOLLOW` prevents the vulnerable symlink-following behavior at the final path component.

The patch then calls `fstat(from_fd, &fsb)` and verifies:

```c
!S_ISREG(fsb.st_mode) || fsb.st_dev != sbp->st_dev ||
    fsb.st_ino != sbp->st_ino
```

This binds the copy operation to the inode selected by the earlier `lstat()`. If the path was replaced after the check, the device or inode no longer matches and the operation aborts with `"changed"` instead of copying attacker-selected content.

The patch also updates `*sbp = fsb` after validation, ensuring subsequent ownership, mode, flags, and timestamp restoration use metadata from the verified opened file descriptor.

## Residual Risk

None

## Patch

```diff
diff --git a/bin/mv/mv.c b/bin/mv/mv.c
index c16b804..61d7cbe 100644
--- a/bin/mv/mv.c
+++ b/bin/mv/mv.c
@@ -262,24 +262,39 @@ int
 fastcopy(char *from, char *to, struct stat *sbp)
 {
 	struct timespec ts[2];
+	struct stat fsb;
 	static u_int32_t blen;
 	static char *bp;
 	int nread, from_fd, to_fd;
 	int badchown = 0, serrno = 0;
 
+	if ((from_fd = open(from, O_RDONLY | O_NONBLOCK | O_NOFOLLOW)) == -1) {
+		warn("%s", from);
+		return (1);
+	}
+	if (fstat(from_fd, &fsb)) {
+		warn("%s", from);
+		(void)close(from_fd);
+		return (1);
+	}
+	if (!S_ISREG(fsb.st_mode) || fsb.st_dev != sbp->st_dev ||
+	    fsb.st_ino != sbp->st_ino) {
+		warnx("%s: changed", from);
+		(void)close(from_fd);
+		return (1);
+	}
+	*sbp = fsb;
+
 	if (!blen) {
 		blen = sbp->st_blksize;
 		if ((bp = malloc(blen)) == NULL) {
 			warn(NULL);
 			blen = 0;
+			(void)close(from_fd);
 			return (1);
 		}
 	}
 
-	if ((from_fd = open(from, O_RDONLY)) == -1) {
-		warn("%s", from);
-		return (1);
-	}
 	if ((to_fd = open(to, O_CREAT | O_TRUNC | O_WRONLY, 0600)) == -1) {
 		warn("%s", to);
 		(void)close(from_fd);
```