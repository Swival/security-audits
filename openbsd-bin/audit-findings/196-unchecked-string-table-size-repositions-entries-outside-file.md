# Unchecked String Table Size Repositions Entries Outside File

## Classification

Memory corruption; high severity.

## Affected Locations

`sbin/restore/symtab.c:601`

## Summary

`initsymtable()` trusted `hdr.stringsize` and `hdr.entrytblsize` from a restart checkpoint file before reconstructing serialized pointers. A crafted checkpoint could make `baseep` point outside the loaded file buffer, causing the reconstruction loop to read and write through out-of-bounds `struct entry *` values.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

`restore` runs in restart or continuation mode on an attacker-controlled symbol table checkpoint file.

## Proof

`initsymtable()` loads the checkpoint body into `base`, then reads the trailing `struct symtableheader`. Before the patch, it computed:

```c
entry = (struct entry **)
	(base + tblsize - (entrytblsize * sizeof(struct entry *)));
baseep = (struct entry *)(base + hdr.stringsize - sizeof(struct entry));
lep = (struct entry *)entry;
```

No validation ensured that `hdr.stringsize`, `hdr.entrytblsize`, `baseep`, `entry`, and `lep` described ranges inside the allocated `base` buffer.

The reproduced case used a negative `stringsize` and positive `entrytblsize`, causing `&baseep[1]` to point before `base` while `lep` still pointed inside or near the allocated buffer. The loop then accessed and rewrote:

```c
ep->e_name
ep->e_parent
ep->e_sibling
ep->e_links
ep->e_entries
ep->e_next
```

An ASan harness equivalent to this code path confirmed that `stringsize = -16`, `tblsize = 256`, and `entrytblsize = 1` starts iteration at `base - 16` and triggers a heap-buffer-overflow on the first field access.

## Why This Is A Real Bug

The checkpoint file is attacker-controlled under the stated precondition, and the vulnerable code directly converts untrusted serialized sizes and indices into in-process pointers. Because `baseep` can be derived outside the allocated checkpoint buffer, the following reconstruction loop performs concrete out-of-bounds reads and writes. This is a memory-safety violation in the `restore` process and can crash or corrupt a privileged process if the checkpoint is consumed by an administrator or root-run restore.

## Fix Requirement

Validate the checkpoint file layout before pointer reconstruction:

- The file must be large enough to contain the trailing header.
- The body size must fit in `long`.
- `entrytblsize` must be positive.
- `stringsize` must be non-negative.
- The entry table must fit inside the loaded body.
- The string table must end before the serialized entry table.
- The remaining serialized entry region must be an integral number of `struct entry` objects.

## Patch Rationale

The patch rejects malformed checkpoint layouts before computing `entry`, `baseep`, or iterating over reconstructed entries.

It first validates the file size before subtracting the header size:

```c
if (stbuf.st_size < (off_t)sizeof(struct symtableheader) ||
    stbuf.st_size - (off_t)sizeof(struct symtableheader) > LONG_MAX)
	panic("corrupted symbol table\n");
```

It then validates the untrusted header-derived regions:

```c
if (hdr.entrytblsize <= 0 || hdr.stringsize < 0 ||
    hdr.entrytblsize > tblsize / (long)sizeof(struct entry *) ||
    hdr.stringsize > tblsize -
    hdr.entrytblsize * (long)sizeof(struct entry *) ||
    (tblsize - hdr.entrytblsize * (long)sizeof(struct entry *) -
    hdr.stringsize) % (long)sizeof(struct entry) != 0)
	panic("corrupted symbol table\n");
```

These checks prevent negative offsets, oversized entry tables, string tables that overlap or exceed the body, and misaligned serialized entry ranges.

## Residual Risk

None

## Patch

`196-unchecked-string-table-size-repositions-entries-outside-file.patch`

```diff
diff --git a/sbin/restore/symtab.c b/sbin/restore/symtab.c
index d4f30a4..12ebde4 100644
--- a/sbin/restore/symtab.c
+++ b/sbin/restore/symtab.c
@@ -544,7 +544,10 @@ initsymtable(char *filename)
 		warn("stat");
 		panic("cannot stat symbol table file %s\n", filename);
 	}
-	tblsize = stbuf.st_size - sizeof(struct symtableheader);
+	if (stbuf.st_size < (off_t)sizeof(struct symtableheader) ||
+	    stbuf.st_size - (off_t)sizeof(struct symtableheader) > LONG_MAX)
+		panic("corrupted symbol table\n");
+	tblsize = stbuf.st_size - (off_t)sizeof(struct symtableheader);
 	base = calloc(tblsize, sizeof(char));
 	if (base == NULL)
 		panic("cannot allocate space for symbol table\n");
@@ -579,6 +582,13 @@ initsymtable(char *filename)
 		panic("initsymtable called from command %c\n", command);
 		break;
 	}
+	if (hdr.entrytblsize <= 0 || hdr.stringsize < 0 ||
+	    hdr.entrytblsize > tblsize / (long)sizeof(struct entry *) ||
+	    hdr.stringsize > tblsize -
+	    hdr.entrytblsize * (long)sizeof(struct entry *) ||
+	    (tblsize - hdr.entrytblsize * (long)sizeof(struct entry *) -
+	    hdr.stringsize) % (long)sizeof(struct entry) != 0)
+		panic("corrupted symbol table\n");
 	maxino = hdr.maxino;
 	entrytblsize = hdr.entrytblsize;
 	entry = (struct entry **)
```