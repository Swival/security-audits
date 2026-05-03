# Negative Quota ID Leaks Uninitialized Quota Reply Fields

## Classification

Information disclosure, high severity, confidence certain.

## Affected Locations

`rpc.rquotad/rquotad.c:253`

## Summary

A remote RPC client using `AUTH_UNIX` credentials can submit a negative `gqa_uid` to `rpc.rquotad`. When `quotactl` fails and the quota-file fallback is reachable, `getfsquota()` uses that negative id to compute the quota-file `lseek()` offset. The negative seek fails, but the error path returns success without initializing `struct dqblk`. `sendquota()` then copies uninitialized stack fields into the `Q_OK` quota response and sends them to the client.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- `rpc.rquotad` accepts a remote `RQUOTAPROC_GETQUOTA` or `RQUOTAPROC_GETACTIVEQUOTA` request.
- The request uses `AUTH_UNIX` credentials.
- The attacker controls `getq_args.gqa_uid` and supplies a negative value.
- The supplied path maps to a configured quota filesystem.
- `quotactl()` fails for that filesystem.
- The configured quota-file fallback can be opened.

## Proof

`sendquota()` declares a stack `struct dqblk dqblk` at `rpc.rquotad/rquotad.c:131` and passes attacker-controlled `getq_args.gqa_uid` to `getfsquota()`.

In `getfsquota()`, the supplied path is matched to a configured filesystem, then `quotactl()` failure falls back to opening the configured quota file. The fallback seek uses:

```c
lseek(fd, (off_t)(id * sizeof(struct dqblk)), SEEK_SET)
```

With a negative `id`, this can produce a negative offset and cause `lseek()` to fail. The original error path at `rpc.rquotad/rquotad.c:253` closed the file descriptor and returned `1`, which is the success value for `getfsquota()`.

`sendquota()` treats that return value as success, sets `getq_rslt.status = Q_OK`, copies fields from the uninitialized `dqblk` into `getquota_rslt`, and sends the response via `svc_sendreply()`.

## Why This Is A Real Bug

The disclosure path is attacker controlled and reaches a network response:

- The remote client controls `getq_args.gqa_uid`.
- Negative ids are not rejected before the fallback quota-file seek.
- The `lseek()` failure path returns success.
- No field of `dqblk` is initialized on that path.
- `sendquota()` serializes `dqblk` fields into the RPC reply when `getfsquota()` returns success.

This produces a concrete remote information disclosure of stack-derived quota reply fields.

## Fix Requirement

- Reject negative quota ids before using them in `quotactl()` or quota-file offset calculations.
- Treat `lseek()` failure as a quota lookup failure, not success.
- Ensure `sendquota()` only serializes `dqblk` after `getfsquota()` has populated or explicitly zeroed it.

## Patch Rationale

The patch adds an early `id < 0` rejection in `getfsquota()`, preventing attacker-supplied negative ids from reaching either `quotactl()` or the fallback `lseek()` offset calculation.

The patch also changes the quota-file `lseek()` error path from `return (1)` to `return (0)`, so failed seeks no longer signal success with an uninitialized `dqblk`.

Together, these changes remove both the triggering input class and the incorrect success return that caused uninitialized stack data to be serialized.

## Residual Risk

None

## Patch

```diff
diff --git a/rpc.rquotad/rquotad.c b/rpc.rquotad/rquotad.c
index 7b2568c..6bebbf3 100644
--- a/rpc.rquotad/rquotad.c
+++ b/rpc.rquotad/rquotad.c
@@ -229,7 +229,7 @@ getfsquota(long id, char *path, struct dqblk *dqblk)
 	struct fs_stat *fs;
 	int	qcmd, fd, ret = 0;
 
-	if (stat(path, &st_path) == -1)
+	if (id < 0 || stat(path, &st_path) == -1)
 		return (0);
 
 	qcmd = QCMD(Q_GETQUOTA, USRQUOTA);
@@ -250,7 +250,7 @@ getfsquota(long id, char *path, struct dqblk *dqblk)
 		if (lseek(fd, (off_t)(id * sizeof(struct dqblk)), SEEK_SET) ==
 		    (off_t)-1) {
 			close(fd);
-			return (1);
+			return (0);
 		}
 		switch (read(fd, dqblk, sizeof(struct dqblk))) {
 		case 0:
```