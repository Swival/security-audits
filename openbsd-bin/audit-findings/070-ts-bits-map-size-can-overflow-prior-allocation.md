# TS_BITS map size can overflow prior allocation

## Classification

High severity out-of-bounds write.

Confidence: certain.

## Affected Locations

`sbin/restore/tape.c:745`

Primary write site:

`sbin/restore/tape.c:805`

`sbin/restore/tape.c:806`

Patched validation site:

`sbin/restore/tape.c:263`

## Summary

`restore` sizes `dumpmap` from the earlier `TS_CLRI` header, but later trusts the independent `TS_BITS` header length when copying bitmap data. A crafted dump archive can set `TS_BITS c_count` larger than the allocation derived from `TS_CLRI c_count`, causing `xtrmap()` to copy past the end of `dumpmap` and corrupt heap memory.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was manually reproduced and patched.

## Preconditions

- `restore` processes attacker-controlled dump input.
- The attacker can craft valid dump headers and recompute the additive dump checksum.
- The archive contains a `TS_BITS` bitmap whose `c_count` exceeds the bitmap capacity implied by the earlier `TS_CLRI` header.

## Proof

`setup()` derives `maxino` from the `TS_CLRI` header:

```c
maxino = (spcl.c_count * TP_BSIZE * NBBY) + 1;
map = calloc(1, howmany(maxino, NBBY));
usedinomap = map;
getfile(xtrmap, xtrmapskip);
```

After reading the next header, `setup()` expects `TS_BITS` and allocates `dumpmap` with the same `howmany(maxino, NBBY)` size:

```c
if (spcl.c_type != TS_BITS)
	errx(1, "Cannot find file dump list");
map = calloc(1, howmany(maxino, NBBY));
dumpmap = map;
getfile(xtrmap, xtrmapskip);
```

For `TS_BITS` and `TS_CLRI`, `gethead()` sets the byte size directly from the current header count:

```c
buf->c_size = buf->c_count * TP_BSIZE;
```

`getfile()` then reads and forwards that claimed size to `xtrmap()` for map extraction. `xtrmap()` performs an unchecked copy and advances the destination pointer:

```c
memcpy(map, buf, size);
map += size;
```

A practical trigger is:

- `TS_CLRI c_count = 1`
- `maxino = 1 * 1024 * 8 + 1`
- allocation size is `howmany(maxino, NBBY) = 1025` bytes
- `TS_BITS c_count = 2`
- copied size is `2 * 1024 = 2048` bytes
- overflow is `2048 - 1025 = 1023` bytes

The checksum does not prevent exploitation because it is an additive checksum over attacker-controlled header fields and can be recomputed.

## Why This Is A Real Bug

The allocation and copy length are controlled by different archive headers. `dumpmap` is allocated using the `TS_CLRI`-derived `maxino`, while `TS_BITS` supplies its own `c_count`, which `gethead()` converts into `spcl.c_size` without checking it against the allocation. `getfile()` consumes that size and `xtrmap()` writes all supplied bytes into `dumpmap`.

Because `xtrmap()` uses `memcpy()` with no remaining-capacity check, any oversized `TS_BITS` map produces a heap write past the allocated buffer. The reproduced `TS_CLRI c_count = 1`, `TS_BITS c_count = 2` case demonstrates deterministic attacker-triggered heap memory corruption.

## Fix Requirement

Before allocating and filling `dumpmap`, validate that `TS_BITS c_count * TP_BSIZE` does not exceed the allocated bitmap size derived from `maxino`.

Malformed archives with oversized `TS_BITS` maps must be rejected before `getfile(xtrmap, xtrmapskip)` is called for the file dump list.

## Patch Rationale

The patch rejects a `TS_BITS` map whose block count exceeds the number of full `TP_BSIZE` blocks that fit in the bitmap allocation:

```c
if (spcl.c_count > howmany(maxino, NBBY) / TP_BSIZE)
	errx(1, "File dump list is too large");
```

This check occurs immediately after confirming the current header is `TS_BITS` and before allocating/filling `dumpmap`. As a result, `getfile()` cannot pass more `TS_BITS` data to `xtrmap()` than the allocation is intended to hold.

## Residual Risk

None

## Patch

```diff
diff --git a/sbin/restore/tape.c b/sbin/restore/tape.c
index fc7f280..79b447c 100644
--- a/sbin/restore/tape.c
+++ b/sbin/restore/tape.c
@@ -263,6 +263,8 @@ setup(void)
 	getfile(xtrmap, xtrmapskip);
 	if (spcl.c_type != TS_BITS)
 		errx(1, "Cannot find file dump list");
+	if (spcl.c_count > howmany(maxino, NBBY) / TP_BSIZE)
+		errx(1, "File dump list is too large");
 	map = calloc(1, howmany(maxino, NBBY));
 	if (map == NULL)
 		panic("no memory for file dump list\n");
```