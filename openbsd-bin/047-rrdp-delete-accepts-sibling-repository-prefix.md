# RRDP delete accepts sibling repository prefix

## Classification

Authorization bypass, medium severity.

## Affected Locations

`usr.sbin/rpki-client/repo.c:643`

## Summary

RRDP delete processing accepted any URI whose bytes started with an authorized `caRepository` URI. Because the authorization check did not require a repository-boundary match, a malicious RRDP publication point could delete cached objects from a sibling repository such as `rsync://host/repo2/file` when authorized only for `rsync://host/repo`.

## Provenance

Verified and reproduced from scanner output attributed to Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The victim uses an RRDP cache.
- The victim has a sibling rsync URI under the same byte prefix, for example:
  - authorized repository: `rsync://host/repo`
  - sibling repository: `rsync://host/repo2`
- The attacker controls a malicious RRDP publication point for the authorized repository.
- The attacker knows the SHA256 digest of the sibling cached object.
- The sibling object is not protected by the current run's `filepath_exists()` reference check during cleanup.

## Proof

For `PUB_DEL`, `rrdp_handle_file()` verifies the supplied hash against an existing object before recording the delete:

- Digest verification occurs in `rrdp_handle_file()` before delete recording.
- For delete elements, the attacker-supplied URI is added to `rr->deleted` via `filepath_add(&rr->deleted, uri, 0, 0, 1)`.
- No repository-boundary authorization is performed at delete-recording time.

Cleanup later processes recorded deletes in `repo_cleanup_rrdp()`:

- Each deleted URI is checked with `rrdp_uri_valid()`.
- The vulnerable implementation used `strncmp(uri, rp->repouri, strlen(rp->repouri)) == 0`.
- Therefore `rsync://host/repo2/file` matched `rp->repouri == rsync://host/repo`.
- After acceptance, `repo_cleanup_rrdp()` calls `rrdp_filename(rr, fp->file, 1)` and then `unlink(fn)` on the valid-cache filename, deleting `host/repo2/file` if it is not currently referenced.

This was reproduced with the sibling URI prefix case described above.

## Why This Is A Real Bug

The security intent is that an RRDP publication point may only delete objects within repositories that depend on that RRDP repository. A raw byte-prefix comparison does not enforce that boundary.

`rsync://host/repo2/file` is not inside `rsync://host/repo`, but it passes the old check because the first `strlen("rsync://host/repo")` bytes are identical. That lets a malicious RRDP operator cross the intended repository boundary and remove a sibling repository's cached object.

## Fix Requirement

The URI authorization check must require an exact repository URI match or a path-boundary match after the repository prefix. The byte following the matched repository prefix must be either:

- string end, for the repository URI itself; or
- `/`, for an object below that repository path.

## Patch Rationale

The patch keeps the existing repository-prefix lookup but adds the missing boundary condition:

```c
len = strlen(rp->repouri);
if (strncmp(uri, rp->repouri, len) == 0 &&
    (uri[len] == '\0' || uri[len] == '/'))
	return 1;
```

This preserves valid deletes for objects actually under the authorized repository while rejecting sibling prefixes such as `rsync://host/repo2/file`.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/rpki-client/repo.c b/usr.sbin/rpki-client/repo.c
index 97d136a..be55ebd 100644
--- a/usr.sbin/rpki-client/repo.c
+++ b/usr.sbin/rpki-client/repo.c
@@ -630,11 +630,14 @@ static int
 rrdp_uri_valid(struct rrdprepo *rr, const char *uri)
 {
 	struct repo *rp;
+	size_t len;
 
 	SLIST_FOREACH(rp, &repos, entry) {
 		if (rp->rrdp != rr)
 			continue;
-		if (strncmp(uri, rp->repouri, strlen(rp->repouri)) == 0)
+		len = strlen(rp->repouri);
+		if (strncmp(uri, rp->repouri, len) == 0 &&
+		    (uri[len] == '\0' || uri[len] == '/'))
 			return 1;
 	}
 	return 0;
```