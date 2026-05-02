# On-Disk Key Count Overwrites icdb Object

## Classification

Memory corruption, high severity. Confidence: certain.

## Affected Locations

`stdlib/icdb.c:184`

## Summary

`icdb_open` trusts the on-disk `info->nkeys` value after validating only the mapped file size, magic, and version. Because `struct icdb` contains only `idxdata[8]`, an attacker-controlled icdb file with `nkeys > 8` causes the initialization loop to write past the end of `idxdata`, corrupting adjacent heap object fields and potentially writing beyond the allocated `struct icdb`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

A victim opens an attacker-controlled icdb file whose header has a matching magic value and expected version.

## Proof

The reproduced analysis confirms:

- `icdb_open` maps the file and casts the mapped header to `struct icdbinfo`.
- Before the patch, validation checks only file size, `info->magic`, and `info->version`.
- `struct icdb` defines `void *idxdata[8]`.
- The loop uses attacker-controlled `info->nkeys` as its bound:

```c
for (i = 0; i < info->nkeys; i++)
	db->idxdata[i] = ptr + sizeof(*info) + i * idxlen;
```

A minimal hostile file with a valid header, matching version, `nkeys = 12`, and `indexsize = 0` reaches this loop. Iterations `i = 8..10` overwrite following fields such as `entries`, `maplen`, `allocated`, or `fd`; iteration `i = 11` writes past the allocated `struct icdb`.

## Why This Is A Real Bug

The on-disk format limits key metadata arrays to eight entries, and newly created databases already reject `nkeys > 8` in `icdb_new`. `icdb_open` lacked the equivalent validation for mapped files, so malformed but otherwise accepted input directly controlled an out-of-bounds write into a heap-allocated object. This is attacker-controlled file parsing leading to memory corruption in the caller process.

## Fix Requirement

Reject mapped icdb headers with `info->nkeys > 8` before allocating or populating the in-memory `struct icdb` auxiliary fields.

## Patch Rationale

The patch adds the missing bound check immediately after magic and version validation and before `db->idxdata` is populated. Returning `EINVAL` for an invalid on-disk key count mirrors the constructor-side constraint and prevents any loop iteration from addressing beyond `idxdata[7]`.

## Residual Risk

None

## Patch

```diff
diff --git a/stdlib/icdb.c b/stdlib/icdb.c
index 2ddd9db..2598930 100644
--- a/stdlib/icdb.c
+++ b/stdlib/icdb.c
@@ -175,6 +175,10 @@ icdb_open(const char *name, int flags, uint32_t version)
 		errno = ENOENT;
 		goto fail;
 	}
+	if (info->nkeys > 8) {
+		errno = EINVAL;
+		goto fail;
+	}
 
 	if (!(db = calloc(1, sizeof(*db))))
 		goto fail;
```