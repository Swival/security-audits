# short backing read writes uninitialized heap into guest disk

## Classification

High severity information disclosure.

Confidence: certain.

## Affected Locations

`usr.sbin/vmd/vioqcow2.c:611`

## Summary

`copy_cluster()` allocated a full cluster-sized heap buffer, accepted any non-error `pread()` result from a qcow2 backing file, and then wrote the entire cluster buffer into the guest-visible writable image. A malicious or truncated backing cluster could cause a positive short read or EOF read, leaving the tail of the heap buffer uninitialized and exposing stale `vmd` heap bytes to the guest disk.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- VM uses an attacker-controlled qcow2 backing chain.
- The backing image maps a virtual cluster to a physical cluster that is truncated or otherwise returns fewer bytes than `disk->clustersz`.
- Guest I/O triggers copy-on-write allocation for that backing-only cluster.

## Proof

In the affected code path:

- `qc2_pwrite()` handles writes to clusters not present in the writable image.
- If the target cluster exists only in a base image, `qc2_pwrite()` calls `mkcluster()`.
- `mkcluster()` allocates a new writable cluster and calls `copy_cluster(disk, base, disk->end, src_phys)`.
- `copy_cluster()` allocates `scratch` with `malloc(disk->clustersz)`.
- The original check only rejected `pread(...) == -1`.
- A positive short read, including EOF after a truncated backing cluster, left the remainder of `scratch` uninitialized.
- `copy_cluster()` then wrote `disk->clustersz` bytes from `scratch` to the writable image with `pwrite()`.
- A later guest read of the unwritten bytes in that cluster returned stale heap contents.

The reproducer confirmed this path: malicious backing metadata can point a cluster at truncated physical storage, causing a short backing read during copy-on-write and making uninitialized heap data visible through `qc2_pread()`.

## Why This Is A Real Bug

`pread()` is permitted to return fewer bytes than requested without returning `-1`, especially near EOF. The original code treated all positive short reads as successful full-cluster reads. Because `scratch` came from `malloc()` rather than zero-initialized allocation, unread bytes retained prior heap contents. Writing the full buffer into the qcow2 image made those bytes durable and guest-visible.

This is not only a malformed-image crash or integrity issue: an attacker controlling the qcow2 backing chain can influence the short-read condition, and the guest can later read the copied cluster tail as disk data, disclosing `vioblk`/`vmd` heap contents.

## Fix Requirement

`copy_cluster()` must not write uninitialized bytes when copying from a backing image. It must either:

- require a full `disk->clustersz` read before writing the cluster, or
- explicitly zero-fill and read in a loop so any missing backing bytes become deterministic zeroes.

## Patch Rationale

The patch changes the read validation from rejecting only `-1` to requiring an exact full-cluster read:

```c
if (pread(base->fd, scratch, disk->clustersz, src) != disk->clustersz)
	fatal("%s: could not read cluster", __func__);
```

This prevents any short backing read from being treated as a valid copy source. Since the subsequent `pwrite()` still writes a full cluster, enforcing a full read ensures every byte written was initialized from the backing image.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/vmd/vioqcow2.c b/usr.sbin/vmd/vioqcow2.c
index 917cba2..290b771 100644
--- a/usr.sbin/vmd/vioqcow2.c
+++ b/usr.sbin/vmd/vioqcow2.c
@@ -589,7 +589,7 @@ copy_cluster(struct qcdisk *disk, struct qcdisk *base, off_t dst, off_t src)
 		fatal("out of memory");
 	src &= ~(disk->clustersz - 1);
 	dst &= ~(disk->clustersz - 1);
-	if (pread(base->fd, scratch, disk->clustersz, src) == -1)
+	if (pread(base->fd, scratch, disk->clustersz, src) != disk->clustersz)
 		fatal("%s: could not read cluster", __func__);
 	if (pwrite(disk->fd, scratch, disk->clustersz, dst) == -1)
 		fatal("%s: could not write cluster", __func__);
```