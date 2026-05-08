# Unterminated Dump Names Reach Sentinel String Compare

## Classification

Out-of-bounds read, medium severity, confidence certain.

## Affected Locations

`sbin/restore/dirs.c:506`

## Summary

`restore` reads attacker-controlled dump directory entries into an internal directory buffer and later treats `d_name` as a NUL-terminated C string. For zero-inode sentinel entries, `rst_readdir()` used `strcmp(dp->d_name, "/")` even though earlier validation only bounded `d_namlen` and record size; it did not prove that `d_name` contains a terminating NUL. A malicious dump entry can therefore cause `strcmp()` to scan past the directory entry while parsing restore directory data.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

`restore` processes attacker-supplied dump directory data.

## Proof

`putdir()` accepts directory records from dump data after validating `d_reclen`, `DIRSIZ(dp)`, and `d_namlen <= NAME_MAX`, then `putent()` copies those records into the temporary restore directory file.

`rst_readdir()` later reads records from that temporary file into `dd_buf` and returns pointers directly into the 1024-byte buffer. Before the patch, it detected the synthetic end-of-directory sentinel with:

```c
if (dp->d_ino == 0 && strcmp(dp->d_name, "/") == 0)
	return (NULL);
```

Because `strcmp()` ignores `d_namlen`, an attacker-controlled record with `d_ino == 0`, `d_namlen == 1`, `d_name[0] == '/'`, and no following NUL byte can make `restore` read past the declared name until an unrelated zero byte is found.

The reproducer confirmed the broader unsafe flow: attacker-supplied records are copied by `putent()`, returned by `rst_readdir()`, and later consumed as C strings by directory traversal logic. An ASan harness matching the committed `putent()` / `rst_readdir()` / string-consumption flow reported a heap-buffer-overflow reading past the `RST_DIR` allocation. The reproduced nonzero-inode path used `strlcat()` rather than the zero-inode `strcmp()` sentinel, but it confirms the same core invariant failure: restored directory names are not guaranteed to be NUL-terminated before C-string APIs consume them.

## Why This Is A Real Bug

The dump image provider controls directory entry bytes. The code validates name length and record length, but length-bounded validation is not equivalent to C-string termination. `strcmp()` requires both inputs to be NUL-terminated; if `dp->d_name` is not terminated within the copied directory record or current buffer, `strcmp()` reads beyond the intended object. This is an attacker-triggerable out-of-bounds read during normal restore parsing and can cause a crash or information-dependent parsing behavior.

## Fix Requirement

Use `d_namlen`-bounded comparisons for directory entry names. Do not call `strcmp()` on dump-provided `d_name` unless the code has first proven that the name is terminated within the validated record.

## Patch Rationale

The patch replaces the sentinel `strcmp()` with an explicit length and byte comparison:

```c
if (dp->d_ino == 0 && dp->d_namlen == 1 &&
    dp->d_name[0] == '/')
	return (NULL);
```

This preserves the intended sentinel check while reading only bytes proven present by the validated `d_namlen` and record-size constraints. It removes the unbounded C-string scan from the zero-inode sentinel path.

## Residual Risk

None

## Patch

```diff
diff --git a/sbin/restore/dirs.c b/sbin/restore/dirs.c
index baebb2c..a35b00b 100644
--- a/sbin/restore/dirs.c
+++ b/sbin/restore/dirs.c
@@ -494,7 +494,8 @@ rst_readdir(RST_DIR *dirp)
 			return (NULL);
 		}
 		dirp->dd_loc += dp->d_reclen;
-		if (dp->d_ino == 0 && strcmp(dp->d_name, "/") == 0)
+		if (dp->d_ino == 0 && dp->d_namlen == 1 &&
+		    dp->d_name[0] == '/')
 			return (NULL);
 		if (dp->d_ino >= maxino) {
 			Dprintf(stderr, "corrupted directory: bad inum %llu\n",
```