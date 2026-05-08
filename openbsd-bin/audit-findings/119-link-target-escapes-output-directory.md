# Link target escapes output directory

## Classification

Path traversal; high severity.

## Affected Locations

`usr.sbin/zic/zic.c:602`

## Summary

A `Link` line in attacker-controlled timezone source can set the `TO` field to an absolute path or a path containing traversal. `zic` later uses that field as a filesystem target and calls `remove(toname)` before link creation, allowing privileged deletion or link creation outside the configured output directory.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

Privileged `zic` processes attacker-controlled timezone source.

## Proof

`inlink` accepted and stored `fields[LF_TO]` without path validation.

`main` later processes stored links with:

```c
dolink(links[i].l_from, links[i].l_to);
```

`dolink` treats an absolute `TO` as the destination path directly:

```c
if (tofield[0] == '/')
	toname = ecpyalloc(tofield);
```

For a relative `TO`, it prepends the output directory but does not reject traversal:

```c
toname = ecpyalloc(directory);
toname = ecatalloc(toname, "/");
toname = ecatalloc(toname, tofield);
```

It then performs filesystem operations on that computed path:

```c
if (!itsdir(toname))
	remove(toname);
```

A malicious timezone source containing:

```text
Link Missing /etc/somefile
```

reaches `remove("/etc/somefile")` when run by privileged `zic`. The `FROM` target does not need to exist because deletion occurs before the later link failure.

Similarly:

```text
Link Missing ../victim
```

with `-d /safe/out` computes `/safe/out/../victim`, escaping the configured output directory.

## Why This Is A Real Bug

The vulnerable path is reachable from normal input parsing. The attacker controls `fields[LF_TO]`, `inlink` stores it, `main` passes it to `dolink`, and `dolink` uses it in `remove`, `link`, and `symlink` without constraining the destination to the output directory.

Because `remove(toname)` happens before validating that `fromname` exists or that `toname` remains under `directory`, the impact includes attacker-controlled deletion outside the output tree with the privileges of the `zic` process.

## Fix Requirement

Reject `Link TO` values that are absolute paths or contain `..` traversal before storing them.

## Patch Rationale

The patch validates the `TO` field in `inlink`, before `l.l_to` is copied into the global links array. Rejecting bad input at parse time prevents any later call to `dolink` from receiving a target that can resolve outside the configured output directory.

The check rejects:

- Absolute paths: `*fields[LF_TO] == '/'`
- Traversal-containing paths: `strstr(fields[LF_TO], "..") != NULL`

This directly blocks the reproduced `/etc/somefile` and `../victim` cases before filesystem operations occur.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/zic/zic.c b/usr.sbin/zic/zic.c
index 1f7aeb8..8fc9ade 100644
--- a/usr.sbin/zic/zic.c
+++ b/usr.sbin/zic/zic.c
@@ -1127,6 +1127,10 @@ inlink(char **fields, int nfields)
 		error("blank TO field on Link line");
 		return;
 	}
+	if (*fields[LF_TO] == '/' || strstr(fields[LF_TO], "..") != NULL) {
+		error("invalid TO field on Link line");
+		return;
+	}
 	l.l_filename = filename;
 	l.l_linenum = linenum;
 	l.l_from = ecpyalloc(fields[LF_FROM]);
```