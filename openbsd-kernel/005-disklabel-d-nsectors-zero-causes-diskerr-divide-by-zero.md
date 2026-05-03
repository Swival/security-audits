# disklabel d_nsectors zero causes diskerr divide-by-zero

## Classification

Denial of service, high severity, confidence certain.

## Affected Locations

- `kern/subr_disk.c:1009`
- `kern/subr_disk.c:1025`
- `kern/subr_disk.c:177`
- `kern/subr_disk.c:258`
- `dev/ata/wd.c:548`

## Summary

A malicious on-disk disklabel with `d_nsectors == 0` can be accepted by disklabel validation and copied into the live kernel disklabel. When a later I/O error is logged through `diskerr()`, the error formatter divides by `DL_SECTOBLK(lp, lp->d_nsectors)`. Since `DL_SECTOBLK()` multiplies by `d_nsectors`, the divisor becomes zero and the kernel panics with a divide-by-zero fault.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- The kernel reads an attacker-controlled disklabel from a disk image or malicious disk backend.
- The label passes existing disklabel validation: valid magic values, partition count, `d_secpercyl`, `d_secsize`, checksum, and version.
- The attacker leaves `d_nsectors == 0`.
- A later I/O error is logged through a `diskerr()` caller with a non-null disklabel and known block offset.

## Proof

The vulnerable path is:

```c
/* checkdisklabel() accepted this before the patch */
else if (dlp->d_secpercyl == 0)
	error = EINVAL;
...
if (lp != dlp)
	*lp = *dlp;
```

Before the patch, `checkdisklabel()` rejected `d_secpercyl == 0` and `d_secsize == 0`, but did not reject `d_nsectors == 0`. A valid malicious label can therefore use `d_secsize = 512`, nonzero `d_secpercyl`, nonzero `d_version`, valid magic values, and a matching checksum while keeping `d_nsectors = 0`.

`diskerr()` later formats transfer errors using the accepted label:

```c
(*pr)(" tn %lld sn %lld)",
    (long long)(sn / DL_SECTOBLK(lp, lp->d_nsectors)),
    (long long)(sn % DL_SECTOBLK(lp, lp->d_nsectors)));
```

`DL_SECTOBLK(lp, lp->d_nsectors)` evaluates to zero when `d_nsectors == 0`, causing both division and modulo by zero.

A reproduced reachable path exists in the `wd` driver: `wddone()` calls `diskerr(..., wd->sc_wdc_bio.blkdone, wd->sc_dk.dk_label)` on DMA, device, timeout, or ATA errors at `dev/ata/wd.c:548`. `blkdone` is initialized to `0`, so `diskerr()` enters the label-formatting block and reaches the zero divisor.

## Why This Is A Real Bug

The value is attacker-controlled through the on-disk disklabel, survives validation, and is copied into the active disklabel. The later divide occurs in kernel error-reporting code, so a malicious ATA or virtual disk backend can first provide the crafted label and then trigger an I/O error to panic the host. The reproduced scope is the `wd`/non-null-label `diskerr()` path, not necessarily every disk driver.

## Fix Requirement

Reject disklabels with `d_nsectors == 0` before they can become active kernel disklabels. The rejection must cover both disklabel reads and disklabel updates.

## Patch Rationale

The patch adds `d_nsectors == 0` validation in both disklabel ingestion paths:

- `checkdisklabel()` now rejects native-endian labels where `d_secpercyl == 0 || d_nsectors == 0`.
- `checkdisklabel()` also rechecks `d_nsectors == 0` after byte-swapped label conversion, so swapped malicious labels are rejected before copying into `lp`.
- `setdisklabel()` now rejects `nlp->d_nsectors == 0`, preventing invalid labels from being installed through label-setting paths.

This prevents the zero value from reaching `diskerr()` and preserves existing behavior for valid labels.

## Residual Risk

None

## Patch

```diff
diff --git a/kern/subr_disk.c b/kern/subr_disk.c
index 0eecefb..d67120e 100644
--- a/kern/subr_disk.c
+++ b/kern/subr_disk.c
@@ -178,7 +178,7 @@ checkdisklabel(dev_t dev, void *rlp, struct disklabel *lp, u_int64_t boundstart,
 		error = ENOENT;	/* no disk label */
 	else if (dlp->d_npartitions > MAXPARTITIONS)
 		error = E2BIG;	/* too many partitions */
-	else if (dlp->d_secpercyl == 0)
+	else if (dlp->d_secpercyl == 0 || dlp->d_nsectors == 0)
 		error = EINVAL;	/* invalid label */
 	else if (dlp->d_secsize == 0)
 		error = ENOSPC;	/* disk too small */
@@ -250,6 +250,9 @@ checkdisklabel(dev_t dev, void *rlp, struct disklabel *lp, u_int64_t boundstart,
 		error = 0;
 	}
 
+	if (dlp->d_nsectors == 0)
+		return (EINVAL);
+
 	/* XXX should verify lots of other fields and whine a lot */
 
 	/* Initial passed in lp contains the real disk size. */
@@ -870,8 +873,8 @@ setdisklabel(struct disklabel *olp, struct disklabel *nlp, u_int64_t openmask)
 	int i;
 
 	/* sanity clause */
-	if (nlp->d_secpercyl == 0 || nlp->d_secsize == 0 ||
-	    (nlp->d_secsize % DEV_BSIZE) != 0)
+	if (nlp->d_secpercyl == 0 || nlp->d_nsectors == 0 ||
+	    nlp->d_secsize == 0 || (nlp->d_secsize % DEV_BSIZE) != 0)
 		return (EINVAL);
 
 	/* special case to allow disklabel to be invalidated */
```