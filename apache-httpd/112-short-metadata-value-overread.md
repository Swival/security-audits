# Short Metadata Value Overread

## Classification

Memory safety, medium severity.

## Affected Locations

`modules/dav/fs/dbm.c:481`

## Summary

`dav_propdb_open()` reads the `METADATA` record from the on-disk DBM property database and copies a full `dav_propdb_metadata` structure from `value.dptr` without first proving that the fetched DBM value is at least `sizeof(dav_propdb_metadata)` bytes. A malformed or corrupted short `METADATA` record therefore causes an out-of-bounds read during property database open.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

A resource property DB contains a `METADATA` record whose value length is shorter than `sizeof(dav_propdb_metadata)`.

## Proof

`dav_propdb_open()` fetches `METADATA` through `dav_dbm_fetch()` and treats any non-NULL value as existing metadata.

The reachable flow is:

- `dav_really_open_db()` calls the provider hook in `modules/dav/main/props.c:512`.
- For the filesystem provider, that hook is `dav_propdb_open()` through `dav_hooks_db_dbm` in `modules/dav/fs/dbm.c:784`.
- `dav_propdb_open()` fetches `METADATA` in `modules/dav/fs/dbm.c:439`.
- It accepts any non-NULL `value.dptr` in `modules/dav/fs/dbm.c:472`.
- It copies `value.dsize` bytes into `db->ns_table` in `modules/dav/fs/dbm.c:477`.
- It then executes `memcpy(&m, value.dptr, sizeof(m))` in `modules/dav/fs/dbm.c:480` without checking `value.dsize >= sizeof(m)`.

A local PoC reproducing the exact pattern with a 1-byte source triggers ASan as a heap-buffer-overflow read of size 4.

## Why This Is A Real Bug

The DBM value length is attacker- or environment-controlled through the persisted property database contents, but the code reads a fixed-size structure from that value unconditionally. If the record is shorter than the structure, `memcpy()` reads past the end of the DBM-provided buffer. This is undefined behavior and can crash the process when a resource property database is opened, including during normal WebDAV property operations such as `PROPFIND` or `PROPPATCH`.

## Fix Requirement

Reject non-NULL `METADATA` values whose `value.dsize` is smaller than `sizeof(dav_propdb_metadata)` before copying into a `dav_propdb_metadata` local.

## Patch Rationale

The patch adds an explicit size check before `memcpy(&m, value.dptr, sizeof(m))`. If the metadata record is too short, the database is closed and the function returns the same class of internal-server-error property database version failure used for incompatible metadata. This prevents the out-of-bounds read while preserving existing error handling behavior for unusable property databases.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/dav/fs/dbm.c b/modules/dav/fs/dbm.c
index 39ab4ad..97e74aa 100644
--- a/modules/dav/fs/dbm.c
+++ b/modules/dav/fs/dbm.c
@@ -477,6 +477,15 @@ static dav_error * dav_propdb_open(apr_pool_t *pool,
         dav_set_bufsize(pool, &db->ns_table, value.dsize);
         memcpy(db->ns_table.buf, value.dptr, value.dsize);
 
+        if (value.dsize < sizeof(m)) {
+            dav_dbm_close(db);
+
+            return dav_new_error(pool, HTTP_INTERNAL_SERVER_ERROR,
+                                 DAV_ERR_PROP_BAD_MAJOR, 0,
+                                 "Prop database has the wrong major "
+                                 "version number and cannot be used.");
+        }
+
         memcpy(&m, value.dptr, sizeof(m));
         if (m.major != DAV_DBVSN_MAJOR) {
             dav_dbm_close(db);
```