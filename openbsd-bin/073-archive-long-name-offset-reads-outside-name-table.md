# archive long-name offset reads outside name table

## Classification

Out-of-bounds read, medium severity.

## Affected Locations

`usr.bin/nm/nm.c:274`

## Summary

`nm` trusts SysV archive long-name offsets before using them as indexes into the archive long-name table. A crafted archive can specify an out-of-range `/offset` member name, causing `strlen(&nametab[i])` to read outside the allocated `nametab` buffer and potentially crash the process.

## Provenance

Verified by reproduced analysis from Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

`nm` processes a SysV archive with a long-name table.

## Proof

`show_archive()` loads the SysV long-name table from the `//` archive member into global `nametab`.

The table bytes are attacker-controlled archive content. After loading, the code only converts embedded newline bytes to NUL bytes; it does not store the table length or append an additional terminator.

Later, normal archive members are passed to `mmbr_name()`. If `nametab` exists and `arh->ar_name[0] == '/'`, `mmbr_name()` treats the member name as a long-name table offset:

```c
i = atol(&arh->ar_name[1]);
len = strlen(&nametab[i]) + 1;
strlcpy(p, &nametab[i], len);
```

There is no validation that `i` is non-negative or less than the allocated long-name table length. A crafted archive can contain a valid `//` long-name table followed by a member header such as `/99999999999999`. That reaches `strlen(&nametab[i])` before object-file validation, allowing attacker-controlled archive bytes to drive an out-of-bounds read.

With a sufficiently large offset, this can dereference unmapped memory and crash `nm`, producing attacker-controlled-file denial of service.

## Why This Is A Real Bug

The archive member name field is attacker-controlled input. The parsed offset is used directly as a pointer offset into `nametab` without bounds checking. `strlen()` then performs an unbounded read from that invalid address until it encounters a NUL byte or faults. The reproducer confirms the vulnerable path is reachable with a crafted archive before object validation rejects the member.

## Fix Requirement

Track the allocated SysV long-name table length and reject any parsed long-name offset that is negative or outside the table before calling `strlen()` or `strlcpy()`.

## Patch Rationale

The patch adds a global `nametablen` alongside `nametab`, initializes it when archive processing starts, records `mmbrlen` when the `//` table is loaded, and clears it when archive processing ends.

`mmbr_name()` now checks:

```c
if (i < 0 || (u_long)i >= nametablen)
	return (1);
```

This prevents forming `&nametab[i]` for offsets outside the allocated table, blocking the out-of-bounds read before `strlen()` and `strlcpy()` execute.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/nm/nm.c b/usr.bin/nm/nm.c
index 41b2540..49119cf 100644
--- a/usr.bin/nm/nm.c
+++ b/usr.bin/nm/nm.c
@@ -293,6 +293,7 @@ process_file(int count, const char *fname)
 }
 
 char *nametab;
+u_long nametablen;
 
 /*
  *
@@ -308,6 +309,8 @@ mmbr_name(struct ar_hdr *arh, char **name, int baselen, int *namelen, FILE *fp)
 		int len;
 
 		i = atol(&arh->ar_name[1]);
+		if (i < 0 || (u_long)i >= nametablen)
+			return (1);
 		len = strlen(&nametab[i]) + 1;
 		if (len > *namelen) {
 			p -= (long)*name;
@@ -500,6 +503,7 @@ show_archive(int count, const char *fname, FILE *fp)
 
 	rval = 0;
 	nametab = NULL;
+	nametablen = 0;
 	symtaboff = 0;
 	symtablen = 0;
 
@@ -550,6 +554,7 @@ show_archive(int count, const char *fname, FILE *fp)
 				break;
 			}
 
+			nametablen = mmbrlen;
 			for (p = nametab, i = mmbrlen; i--; p++)
 				if (*p == '\n')
 					*p = '\0';
@@ -618,6 +623,7 @@ skip:		if (fseeko(fp, last_ar_off + even(mmbrlen), SEEK_SET)) {
 	}
 	free(nametab);
 	nametab = NULL;
+	nametablen = 0;
 	free(name);
 	return(rval);
 }
```