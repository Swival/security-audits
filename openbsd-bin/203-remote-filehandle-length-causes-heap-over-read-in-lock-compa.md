# Remote Filehandle Length Causes Heap Over-Read In Lock Comparison

## Classification

High severity out-of-bounds read in remote RPC request handling.

Confidence: certain.

## Affected Locations

`usr.sbin/rpc.lockd/lockd_lock.c:54`

## Summary

`rpc.lockd` stores remote NLM filehandles with their RPC-provided length, but compared them using `memcmp(..., sizeof(fhandle_t))` regardless of the allocated buffer size. A remote client could send a short filehandle that reaches lock comparison against an existing tracked lock, causing `memcmp()` to read past the heap allocation.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

## Preconditions

`rpc.lockd` has at least one tracked lock to compare against.

## Proof

`fhconv()` accepts any remote filehandle length up to `FHANDLE_SIZE_MAX`, allocates exactly that size with `malloc(sz)`, records it in `fhsize`, and copies `sz` bytes from the RPC `netobj`.

Before the patch, `fhcmp()` ignored `fhsize`:

```c
return memcmp(fh1->fhdata, fh2->fhdata, sizeof(fhandle_t));
```

With an existing lock present, a remote NLM client can submit a short filehandle, for example `n_len = 1`, whose first byte matches the existing filehandle prefix. The request then reaches comparison paths including:

- `nlm4_test_4_svc()` -> `testlock(&arg->alock, LOCK_V4)` -> `fhcmp(&fl->filehandle, &filehandle)`
- `nlm4_lock_4_svc()` -> `getlock(arg, ...)` -> `lock_lookup(..., LL_FH ...)`
- `unlock()` -> `fhcmp(&filehandle, &fl->filehandle)`
- `do_unlock()` -> waiting-lock comparison via `fhcmp(&rfl->filehandle, &fl->filehandle)`

Because the attacker-controlled buffer may be smaller than `sizeof(fhandle_t)`, the fixed-size `memcmp()` reads beyond the heap allocation when the common prefix does not differ before the short allocation ends.

## Why This Is A Real Bug

The allocation size is attacker-controlled through the RPC filehandle length, bounded only by `FHANDLE_SIZE_MAX`. The comparison size was a fixed local kernel filehandle structure size, not the recorded allocation length. Therefore, valid control flow through lock lookup can make a long-running remote daemon perform an out-of-bounds heap read from attacker-influenced input.

The bug is reachable remotely through NLM procedures once any tracked lock exists, and has practical denial-of-service potential depending on allocator layout.

## Fix Requirement

Compare recorded filehandle lengths first. Only call `memcmp()` when the lengths are equal, and compare exactly the recorded filehandle length.

## Patch Rationale

The patch changes `fhcmp()` to reject unequal-length filehandles before comparing contents:

```c
if (fh1->fhsize != fh2->fhsize)
	return 1;
return memcmp(fh1->fhdata, fh2->fhdata, fh1->fhsize);
```

This preserves equality semantics for filehandles while ensuring `memcmp()` never reads beyond either allocation. If lengths differ, the filehandles cannot be equal and no byte comparison is needed. If lengths match, both buffers were allocated with that recorded size by `fhconv()`.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/rpc.lockd/lockd_lock.c b/usr.sbin/rpc.lockd/lockd_lock.c
index bb751cb..a36baed 100644
--- a/usr.sbin/rpc.lockd/lockd_lock.c
+++ b/usr.sbin/rpc.lockd/lockd_lock.c
@@ -58,7 +58,9 @@ typedef struct {
 static int
 fhcmp(const nfs_fhandle_t *fh1, const nfs_fhandle_t *fh2)
 {
-	return memcmp(fh1->fhdata, fh2->fhdata, sizeof(fhandle_t));
+	if (fh1->fhsize != fh2->fhsize)
+		return 1;
+	return memcmp(fh1->fhdata, fh2->fhdata, fh1->fhsize);
 }
 
 static int
```