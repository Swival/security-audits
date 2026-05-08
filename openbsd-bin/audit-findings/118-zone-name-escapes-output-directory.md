# Zone Name Escapes Output Directory

## Classification

Path traversal, high severity.

## Affected Locations

- `usr.sbin/zic/zic.c:1372`
- `usr.sbin/zic/zic.c:955`
- `usr.sbin/zic/zic.c:2246`
- `usr.sbin/zic/zic.c:1414`
- `usr.sbin/zic/zic.c:1420`
- `usr.sbin/zic/zic.c:1422`

## Summary

`zic` accepted attacker-controlled `Zone` names containing `..` path components. The accepted name was later concatenated with the configured output directory and used for `remove()` and `fopen("wb")`, allowing deletion or overwrite outside the output directory.

The patch rejects absolute paths and any `..` path component in both `Zone` and `Link` names before they reach filesystem operations.

## Provenance

Verified and patched from Swival Security Scanner finding: https://swival.dev

Confidence: certain.

## Preconditions

- `zic` runs with write permission outside the configured output directory.
- A lower-privileged local user can supply timezone source input to that `zic` invocation.

## Proof

A minimal malicious timezone source is:

```text
Zone ../victim 0 - UTC
```

When run as:

```sh
zic -d /tmp/out attacker.tz
```

the vulnerable flow is:

- `inzone` accepts `fields[ZF_NAME]` without rejecting `../victim`.
- `inzsub` stores it as `z.z_name` via `ecpyalloc(fields[ZF_NAME])`.
- `outzone` passes `zpfirst->z_name` to `writezone`.
- `writezone` builds `fullname` with `snprintf(fullname, len, "%s/%s", directory, name)`.
- This produces `/tmp/out/../victim`, resolving to `/tmp/victim`.
- `writezone` then calls `remove(fullname)` and `fopen(fullname, "wb")`.

If permissions allow, `/tmp/victim` is unlinked and replaced with generated tzfile data.

## Why This Is A Real Bug

The configured output directory is intended to constrain generated timezone files. Concatenating `directory/name` does not provide confinement when `name` contains path traversal components.

`itsdir()` only avoids removing directories and does not verify that the resolved path remains below `directory`. OpenBSD `pledge("... wpath cpath ...")` permits write and create path operations and is not a path confinement mechanism.

The same path-construction pattern exists for links, so `Link` names also require validation.

## Fix Requirement

Reject:

- Absolute `Zone` and `Link` paths.
- Any `Zone` or `Link` path component exactly equal to `..`.

Valid relative timezone names with ordinary subdirectories remain allowed.

## Patch Rationale

The patch adds `isvalidpath(const char *name)` and calls it during parsing:

- `inzone` rejects invalid `fields[ZF_NAME]` before storing the zone name.
- `inlink` rejects invalid `fields[LF_FROM]` and `fields[LF_TO]` before storing link names.

`isvalidpath` checks:

- `name[0] == '/'` is invalid.
- Each slash-delimited component is scanned.
- Any component with length 2 and content `..` is invalid.
- Other relative names are accepted.

This blocks traversal before data reaches `writezone()` or `dolink()`.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/zic/zic.c b/usr.sbin/zic/zic.c
index 1f7aeb8..7369d11 100644
--- a/usr.sbin/zic/zic.c
+++ b/usr.sbin/zic/zic.c
@@ -119,6 +119,7 @@ static void	inrule(char **fields, int nfields);
 static int	inzcont(char **fields, int nfields);
 static int	inzone(char **fields, int nfields);
 static int	inzsub(char **fields, int nfields, int iscont);
+static int	isvalidpath(const char *name);
 static int	itsdir(const char *name);
 static int	mkdirs(char *filename);
 static void	newabbr(const char *abbr);
@@ -883,6 +884,25 @@ inrule(char **fields, int nfields)
 	rules[nrules++] = r;
 }
 
+static int
+isvalidpath(const char *name)
+{
+	const char	*cp;
+	size_t		len;
+
+	if (*name == '/')
+		return FALSE;
+	for (cp = name; ; ) {
+		len = strcspn(cp, "/");
+		if (len == 2 && cp[0] == '.' && cp[1] == '.')
+			return FALSE;
+		cp += len;
+		if (*cp == '\0')
+			return TRUE;
+		++cp;
+	}
+}
+
 static int
 inzone(char **fields, int nfields)
 {
@@ -892,6 +912,10 @@ inzone(char **fields, int nfields)
 		error("wrong number of fields on Zone line");
 		return FALSE;
 	}
+	if (!isvalidpath(fields[ZF_NAME])) {
+		error("invalid zone name");
+		return FALSE;
+	}
 	if (strcmp(fields[ZF_NAME], TZDEFAULT) == 0 && lcltime != NULL) {
 		error("\"Zone %s\" line and -l option are mutually exclusive",
 		    TZDEFAULT);
@@ -1127,6 +1151,10 @@ inlink(char **fields, int nfields)
 		error("blank TO field on Link line");
 		return;
 	}
+	if (!isvalidpath(fields[LF_FROM]) || !isvalidpath(fields[LF_TO])) {
+		error("invalid link name");
+		return;
+	}
 	l.l_filename = filename;
 	l.l_linenum = linenum;
 	l.l_from = ecpyalloc(fields[LF_FROM]);
```