# Unbounded Owner String Scan

## Classification

Memory safety, medium severity.

## Affected Locations

`modules/dav/lock/locks.c:523`

The same parsing pattern also affected the direct-lock `auth_user` field in `modules/dav/lock/locks.c`.

## Summary

`dav_generic_load_lock_record()` parsed direct lock records from the lock DB using `strlen()` on string fields fetched as bounded DBM data. If a direct lock record contained unterminated owner bytes, `strlen(val.dptr + offset)` could scan past `val.dsize`, causing an out-of-bounds read during normal lock retrieval.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The lock database contains a direct lock record.
- The direct lock record reaches the owner field.
- The owner bytes are not NUL-terminated within the fetched DBM datum.

## Proof

`apr_dbm_fetch()` returns the stored lock DB value into `val`, with its valid extent described by `val.dptr` and `val.dsize`.

For `DAV_LOCK_DIRECT`, the parser advances `offset` past:

- the record type byte,
- `dav_lock_discovery_fixed`,
- the lock token.

It then parses `owner` with:

```c
apr_size_t len = strlen(val.dptr + offset);
```

There was no check that a terminating NUL existed between `val.dptr + offset` and `val.dptr + val.dsize`. A malformed DB record shaped as:

```text
DAV_LOCK_DIRECT || fixed fields || token || non-NUL owner bytes
```

with no terminating NUL causes `strlen()` to read beyond the fetched datum.

The reproduced ASan harness mirroring the direct-lock parse triggered a heap-buffer-overflow in `strlen()` when the owner field ended at the end of the fetched datum without a NUL terminator.

The reachable call path is:

```text
dav_lock_query()
hooks->get_locks()
dav_generic_get_locks()
dav_generic_load_lock_record()
```

The same unbounded parsing pattern existed for `auth_user`.

## Why This Is A Real Bug

DBM values are byte arrays with explicit sizes, not guaranteed C strings. Calling `strlen()` on a pointer into such a datum is only safe if the parser first proves that a NUL byte exists within the remaining `val.dsize - offset` bytes.

Without that proof, malformed local lock DB contents can cause out-of-bounds reads. Practical impact is at least process crash / denial of service. If a NUL byte is found past the datum, out-of-bounds data may also be copied into pool memory via `apr_pstrmemdup()`.

## Fix Requirement

Replace unbounded `strlen()` scans for serialized direct-lock string fields with bounded searches constrained to the remaining fetched DBM datum.

If no NUL terminator exists within `val.dsize - offset`, parsing must fail with a corrupt lock DB error and free the fetched datum.

## Patch Rationale

The patch uses:

```c
memchr(val.dptr + offset, '\0', val.dsize - offset)
```

for both `owner` and `auth_user`.

This keeps parsing within the DBM datum bounds, preserves existing handling of empty strings, duplicates only bytes proven to belong to the fetched record, and reports malformed records as corrupt lock DB entries instead of allowing an out-of-bounds read.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/dav/lock/locks.c b/modules/dav/lock/locks.c
index 0f072ec..07872b7 100644
--- a/modules/dav/lock/locks.c
+++ b/modules/dav/lock/locks.c
@@ -631,22 +631,42 @@ static dav_error * dav_generic_load_lock_record(dav_lockdb *lockdb,
             offset += sizeof(*dp->locktoken);
 
             /* Do we have an owner field? */
-            if (*(val.dptr + offset) == '\0') {
-                ++offset;
-            }
-            else {
-                apr_size_t len = strlen(val.dptr + offset);
-                dp->owner = apr_pstrmemdup(p, val.dptr + offset, len);
-                offset += len + 1;
+            {
+                const char *eos = memchr(val.dptr + offset, '\0',
+                                         val.dsize - offset);
+                if (eos == NULL) {
+                    apr_dbm_freedatum(lockdb->info->db, val);
+                    return dav_new_error(p, HTTP_INTERNAL_SERVER_ERROR,
+                                         DAV_ERR_LOCK_CORRUPT_DB, 0,
+                                         "The lock database was found to be corrupt.");
+                }
+                if (eos == val.dptr + offset) {
+                    ++offset;
+                }
+                else {
+                    apr_size_t len = eos - (val.dptr + offset);
+                    dp->owner = apr_pstrmemdup(p, val.dptr + offset, len);
+                    offset += len + 1;
+                }
             }
 
-            if (*(val.dptr + offset) == '\0') {
-                ++offset;
-            }
-            else {
-                apr_size_t len = strlen(val.dptr + offset);
-                dp->auth_user = apr_pstrmemdup(p, val.dptr + offset, len);
-                offset += len + 1;
+            {
+                const char *eos = memchr(val.dptr + offset, '\0',
+                                         val.dsize - offset);
+                if (eos == NULL) {
+                    apr_dbm_freedatum(lockdb->info->db, val);
+                    return dav_new_error(p, HTTP_INTERNAL_SERVER_ERROR,
+                                         DAV_ERR_LOCK_CORRUPT_DB, 0,
+                                         "The lock database was found to be corrupt.");
+                }
+                if (eos == val.dptr + offset) {
+                    ++offset;
+                }
+                else {
+                    apr_size_t len = eos - (val.dptr + offset);
+                    dp->auth_user = apr_pstrmemdup(p, val.dptr + offset, len);
+                    offset += len + 1;
+                }
             }
 
             if (!dav_generic_lock_expired(dp->f.timeout)) {
```