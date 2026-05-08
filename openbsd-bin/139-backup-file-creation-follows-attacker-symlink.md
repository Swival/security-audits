# Backup File Creation Follows Attacker Symlink

## Classification

Path traversal / symlink-following file overwrite.

Severity: medium.

Confidence: certain.

## Affected Locations

`usr.bin/indent/indent.c:1036`

`usr.bin/indent/indent.c:1307`

`usr.bin/indent/indent.c:1311`

`usr.bin/indent/indent.c:1314`

`usr.bin/indent/indent.c:1315`

## Summary

`bakcopy()` creates a predictable backup path from the input basename as `%s.BAK`, then opens it with `O_CREAT | O_TRUNC | O_WRONLY`. Because the open does not use `O_NOFOLLOW` or exclusive creation, an attacker who controls the working directory can precreate `basename.BAK` as a symlink. When a victim runs `indent` on the matching basename, `open()` follows the symlink, truncates the target, and writes the input file contents into it.

## Provenance

Identified by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched from the supplied vulnerable source and reproducer summary.

## Preconditions

- Victim runs `indent` in an attacker-writable directory.
- Victim formats a file whose basename matches an attacker-precreated `basename.BAK` symlink.
- The symlink target is writable by the victim.
- The attacker is a lower-privileged local user who can control the shared directory but cannot otherwise modify the symlink target directly.

## Proof

`bakcopy()` derives the backup filename from the basename of `in_name`:

```c
if (snprintf(bakfile, PATH_MAX, "%s.BAK", p) >= PATH_MAX)
	errc(1, ENAMETOOLONG, "%s.BAK", p);
```

It then opens that predictable path destructively:

```c
bakchn = open(bakfile, O_CREAT | O_TRUNC | O_WRONLY, 0600);
```

If `foo.c.BAK` already exists as a symlink, this `open()` follows the link and `O_TRUNC` truncates the symlink target. The following loop copies the original input bytes into that opened target:

```c
while ((n = read(fileno(input), buff, sizeof buff)) > 0)
	if (write(bakchn, buff, n) != n)
	    err(1, "%s", bakfile);
```

Reproduced impact: a lower-privileged local attacker controlling a shared directory can cause a victim running `indent foo.c` to overwrite a victim-writable file selected by the attacker through the precreated `foo.c.BAK` symlink.

## Why This Is A Real Bug

The backup file name is predictable and located in the current working directory using the input basename. The creation path is not safe against preexisting filesystem objects. `O_TRUNC` makes the failure mode destructive, and the absence of `O_NOFOLLOW` allows symlink traversal. This creates a practical confused-deputy overwrite primitive whenever the victim has write permission to the symlink target.

## Fix Requirement

Create the backup file only if it does not already exist and never follow symlinks during creation. The operation must fail on attacker-precreated backup paths, including symlinks.

## Patch Rationale

Replacing `O_TRUNC` with `O_EXCL` prevents reuse of any existing backup path. Adding `O_NOFOLLOW` explicitly rejects symlink traversal. Keeping `O_CREAT | O_WRONLY` preserves the intended behavior of creating and writing a new backup file, while converting unsafe preexisting-path cases into errors.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/indent/indent.c b/usr.bin/indent/indent.c
index 8679c11..7ae97a7 100644
--- a/usr.bin/indent/indent.c
+++ b/usr.bin/indent/indent.c
@@ -1308,7 +1308,7 @@ bakcopy(void)
 	    errc(1, ENAMETOOLONG, "%s.BAK", p);
 
     /* copy in_name to backup file */
-    bakchn = open(bakfile, O_CREAT | O_TRUNC | O_WRONLY, 0600);
+    bakchn = open(bakfile, O_CREAT | O_EXCL | O_NOFOLLOW | O_WRONLY, 0600);
     if (bakchn == -1)
 	err(1, "%s", bakfile);
     while ((n = read(fileno(input), buff, sizeof buff)) > 0)
```