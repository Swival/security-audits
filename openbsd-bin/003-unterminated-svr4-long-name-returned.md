# Unterminated SVR4 Long Name Returned

## Classification

Out-of-bounds read.

Severity: medium.

Confidence: certain.

## Affected Locations

- `make/arch.c:686`

## Summary

`ArchSVR4Entry` can return a pointer into an SVR4 archive long-name table that is not NUL-terminated within the allocated table. `read_archive` then treats that pointer as a C string while hashing archive members, causing reads past the heap allocation.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced with an attacker-controlled SVR4 archive containing an unterminated long-name table entry.

## Preconditions

- `make` hashes an attacker-supplied SVR4 archive with long-name entries.
- The archive contains a `//` long-name table.
- A later member uses a `/<offset>` name that points inside the table.
- The referenced bytes contain no `/` separator and no NUL terminator before the end of the table.

## Proof

A reproducer used an archive with:

- A `//` SVR4 long-name table of size 4 containing `ABCD`.
- No `/` byte and no NUL byte in that table.
- A later member named `/0`.

The vulnerable flow is:

- `ArchSVR4Entry` allocates exactly `size` bytes for `l->fnametab`.
- It reads the attacker-controlled name table into that allocation.
- It only replaces `/` bytes with `'\0'`.
- It accepts `/0` because `entry < l->fnamesize`.
- It returns `l->fnametab + entry`.
- `read_archive` passes the returned pointer to `ohash_qlookup` and `new_arch_member` as a C string.

Because the table is `ABCD` with no terminator, C-string consumers read past the 4-byte heap allocation.

Runtime confirmation from an ASan harness following the same committed-source logic reported a heap-buffer-overflow reading exactly past the 4-byte name-table allocation.

## Why This Is A Real Bug

The SVR4 long-name table is attacker-controlled archive data. The existing bounds check only validates that the requested offset starts inside `l->fnametab`; it does not validate that a complete NUL-terminated string exists from that offset to `l->fnametab + l->fnamesize`.

`ArchSVR4Entry` therefore returns a pointer that may not designate a valid C string. Immediate downstream uses require a valid C string and can read beyond the heap buffer while computing hashes or copying member names. This is a concrete out-of-bounds read with practical build-process denial-of-service potential.

## Fix Requirement

Reject SVR4 long-name offsets unless the referenced name has a NUL terminator within the bounds of `l->fnametab`.

## Patch Rationale

The patch adds a bounded terminator check after validating `entry < l->fnamesize` and before returning `l->fnametab + entry`.

```c
if (memchr(l->fnametab + entry, '\0', l->fnamesize - entry) == NULL) {
	if (DEBUG(ARCH))
		printf("SVR4 entry offset /%s has no terminator\n", name);
	return NULL;
}
```

This preserves valid SVR4 entries, because `/` separators in the long-name table are already converted to `'\0'`. It rejects malformed entries whose referenced string would otherwise run off the end of the allocated table.

## Residual Risk

None

## Patch

```diff
diff --git a/make/arch.c b/make/arch.c
index 9fb18db..ab6a261 100644
--- a/make/arch.c
+++ b/make/arch.c
@@ -669,6 +669,11 @@ ArchSVR4Entry(struct SVR4namelist *l, const char *name, size_t size, FILE *arch)
 			    name, l->fnamesize);
 		return NULL;
 	}
+	if (memchr(l->fnametab + entry, '\0', l->fnamesize - entry) == NULL) {
+		if (DEBUG(ARCH))
+			printf("SVR4 entry offset /%s has no terminator\n", name);
+		return NULL;
+	}
 
 	if (DEBUG(ARCH))
 		printf("Replaced /%s with %s\n", name, l->fnametab + entry);
```