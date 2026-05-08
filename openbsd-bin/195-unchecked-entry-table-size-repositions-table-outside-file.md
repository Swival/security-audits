# unchecked entry table size repositions table outside file

## Classification

High severity out-of-bounds write.

## Affected Locations

`sbin/restore/symtab.c:598`

## Summary

`initsymtable()` trusts `hdr.entrytblsize` from an attacker-controlled restore symbol table footer. A crafted value can move the reconstructed `entry` table pointer outside the allocated file buffer, causing out-of-bounds reads and writes during pointer relocation in a privileged `restore` restart or continuation.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

A privileged `restore` process opens an attacker-controlled symbol table file for restart or continuation.

## Proof

`initsymtable()` reads the checkpoint body into `base`, then reads `struct symtableheader hdr` from the file footer. It assigns:

```c
entrytblsize = hdr.entrytblsize;
entry = (struct entry **)
    (base + tblsize - (entrytblsize * sizeof(struct entry *)));
```

Before the patch, `hdr.entrytblsize` was not checked against `st_size`, `tblsize`, or `hdr.stringsize`.

A crafted `entrytblsize` can place `entry` before or after the allocated `base` buffer. The subsequent loop dereferences and writes through that attacker-positioned table:

```c
for (i = 0; i < entrytblsize; i++) {
    if (entry[i] == NULL)
        continue;
    entry[i] = &baseep[(long)entry[i]];
}
```

The reproducer confirmed the read side with an ASan harness: `entry[0]` was read 8 bytes before the allocation, producing a heap-buffer-overflow. The write side is also present in source: if the out-of-bounds table word is non-NULL, the relocation assignment writes back through the same out-of-bounds slot. A signed negative `hdr.entrytblsize` can also move `lep` past the buffer and cause the later relocation loop to store through `ep` outside the allocation.

## Why This Is A Real Bug

The checkpoint file is attacker-controlled under the stated restart/continuation precondition, and the existing date, volume, and tape checks do not validate the serialized table layout. `hdr.entrytblsize` directly controls pointer reconstruction before any bounds check. This reaches concrete out-of-bounds memory access in the privileged process, with ASan reproduction for the read and source-supported write/corruption paths.

## Fix Requirement

Validate the symbol table file size and footer-derived layout fields before deriving any in-buffer pointers. Specifically:

- Reject files smaller than `struct symtableheader`.
- Reject negative or oversized `hdr.stringsize`.
- Reject non-positive `hdr.entrytblsize`.
- Reject `hdr.entrytblsize` values whose pointer table cannot fit in the remaining body after `hdr.stringsize`.

## Patch Rationale

The patch first ensures `stbuf.st_size` can contain the footer before subtracting `sizeof(struct symtableheader)`, preventing underflow in `tblsize`.

After reading the footer, it validates the serialized layout before computing `entry` or `baseep`. The check:

```c
hdr.entrytblsize > (tblsize - hdr.stringsize) /
    (long)sizeof(struct entry *)
```

ensures the reconstructed pointer table fits within the file body after the string area. This prevents attacker-controlled `entrytblsize` from repositioning `entry` outside the allocated `base` buffer.

## Residual Risk

None

## Patch

```diff
diff --git a/sbin/restore/symtab.c b/sbin/restore/symtab.c
index d4f30a4..5210a8d 100644
--- a/sbin/restore/symtab.c
+++ b/sbin/restore/symtab.c
@@ -544,6 +544,8 @@ initsymtable(char *filename)
 		warn("stat");
 		panic("cannot stat symbol table file %s\n", filename);
 	}
+	if (stbuf.st_size < (off_t)sizeof(struct symtableheader))
+		panic("symbol table file %s too small\n", filename);
 	tblsize = stbuf.st_size - sizeof(struct symtableheader);
 	base = calloc(tblsize, sizeof(char));
 	if (base == NULL)
@@ -554,6 +556,11 @@ initsymtable(char *filename)
 		panic("cannot read symbol table file %s\n", filename);
 	}
 	close(fd);
+	if (hdr.stringsize < 0 || hdr.stringsize > tblsize ||
+	    hdr.entrytblsize <= 0 ||
+	    hdr.entrytblsize > (tblsize - hdr.stringsize) /
+	    (long)sizeof(struct entry *))
+		panic("corrupt symbol table file %s\n", filename);
 	switch (command) {
 	case 'r':
 		/*
```