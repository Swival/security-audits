# dot-dot escapes YP map root

## Classification

High severity path traversal.

## Affected Locations

`usr.sbin/ypserv/ypserv/ypserv_db.c:256`

## Summary

`ypdb_open_db` accepts remote YP `domain` and `map` strings, rejects only `/`, and then builds a filesystem path as `YP_DB_PATH/domain/map`. A domain value of `..` is slash-free but resolves outside the configured YP database root, allowing a remote YP client to cause `ypserv` to open and disclose records from sibling DBM files.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

The target DBM map exists at the parent path with the requested map name.

## Proof

A remote YP client can send a lookup request with:

- `domain = ".."`
- `map = <slash-free map name>`

Reachability is confirmed through the RPC path:

- `ypserv.c:245` dispatches remote `YPPROC_MATCH` through `xdr_ypreq_key` to `ypproc_match_2_svc`.
- `ypproc_match_2_svc` rejects only `/` in `domain` or `map`.
- `ypproc_match_2_svc` calls `ypdb_get_record` at `usr.sbin/ypserv/ypserv/ypserv_proc.c:143` and `usr.sbin/ypserv/ypserv/ypserv_proc.c:159`.
- `ypdb_get_record` calls `ypdb_open_db`.
- `ypdb_open_db` rejects only `/`, so `..` passes validation.
- `ypdb_open_db` builds `"%s/%s/%s"` as `/var/yp/../<map>` at `usr.sbin/ypserv/ypserv/ypserv_db.c:241` and `usr.sbin/ypserv/ypserv/ypserv_db.c:257`.
- `ypdb_open` appends `.db` and calls `dbopen`, opening `/var/yp/../<map>.db`, which resolves to `/var/<map>.db`, at `usr.sbin/ypserv/common/ypdb.c:68`.
- If that DBM exists and is readable by the root-running server, `ypdb_fetch` returns records.
- `ypdb_get_record` places the returned value in the RPC response at `usr.sbin/ypserv/ypserv/ypserv_db.c:467` and `usr.sbin/ypserv/ypserv/ypserv_db.c:480`.

Result: DBM records outside `YP_DB_PATH` are disclosed to the remote client.

## Why This Is A Real Bug

The validation checks only for literal slash characters, but path traversal does not require a slash inside the attacker-controlled component when the program itself inserts separators between path components. `domain = ".."` is accepted, then combined into `/var/yp/../<map>`, escaping the intended `/var/yp` database tree.

The vulnerable path is reachable from remote YP lookup handling, and the fetched DBM value is returned in the RPC response. This produces a concrete confidentiality impact when a sibling DBM exists.

## Fix Requirement

Reject `.` and `..` path components before building `map_path`.

Both `domain` and `map` must be checked because either value is used as an individual path component in `YP_DB_PATH/domain/map`.

## Patch Rationale

The patch keeps the existing slash rejection and adds exact rejection for `.` and `..` in both path components:

- `domain = "."` and `domain = ".."` now return `YP_NODOM`.
- `map = "."` and `map = ".."` now return `YP_NOMAP`.
- Normal domain and map names remain accepted.
- The check occurs before `snprintf`, so traversal components cannot enter the constructed path.

This directly blocks the reproduced escape primitive without changing DBM open behavior or valid map lookup semantics.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/ypserv/ypserv/ypserv_db.c b/usr.sbin/ypserv/ypserv/ypserv_db.c
index 47dcd95..d05ff08 100644
--- a/usr.sbin/ypserv/ypserv/ypserv_db.c
+++ b/usr.sbin/ypserv/ypserv/ypserv_db.c
@@ -238,11 +238,13 @@ ypdb_open_db(domainname domain, mapname map, ypstat *status,
 
 	/* Check for illegal charcaters */
 
-	if (strchr(domain, '/')) {
+	if (strchr(domain, '/') || strcmp(domain, ".") == 0 ||
+	    strcmp(domain, "..") == 0) {
 		*status = YP_NODOM;
 		return (NULL);
 	}
-	if (strchr(map, '/')) {
+	if (strchr(map, '/') || strcmp(map, ".") == 0 ||
+	    strcmp(map, "..") == 0) {
 		*status = YP_NOMAP;
 		return (NULL);
 	}
```