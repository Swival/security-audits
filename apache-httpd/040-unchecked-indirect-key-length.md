# Unchecked Indirect Key Length

## Classification

Validation gap, medium severity.

## Affected Locations

`modules/dav/lock/locks.c:554`

## Summary

`dav_generic_load_lock_record()` trusted serialized lock data fetched from the DBM lock database. For indirect lock records, it read `ip->key.dsize` from the record and used it as the length for `apr_pmemdup()` without first verifying that the DB value still contained that many bytes. A malformed indirect record could therefore cause an out-of-bounds read while loading locks for a resource.

## Provenance

Verified from the supplied reproducer and patch material.

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The DAV generic lock database contains a malformed indirect lock record.
- A request or internal path loads locks for the affected resource.
- The malformed record encodes an indirect lock with a key length larger than the remaining fetched DBM value.

## Proof

`apr_dbm_fetch()` returns the DB value as `val.dptr` and `val.dsize`.

In `dav_generic_load_lock_record()`, an indirect lock record is parsed as:

- `DAV_LOCK_INDIRECT`
- `apr_uuid_t locktoken`
- `time_t timeout`
- `int key_size`
- `char[] key`

Before the patch, the parser advanced `offset` through those fields and then executed:

```c
ip->key.dsize = *((int *) (val.dptr + offset));
offset += sizeof(ip->key.dsize);
ip->key.dptr = apr_pmemdup(p, val.dptr + offset, ip->key.dsize);
offset += ip->key.dsize;
```

There was no validation that `ip->key.dsize <= val.dsize - offset`.

A malformed DB record such as:

```text
[DAV_LOCK_INDIRECT][uuid][timeout][key_size=large][short or missing key bytes]
```

reaches the `apr_pmemdup()` call and reads past the end of the fetched DBM value. The same parser also lacked bounds checks before several fixed-length direct and indirect record reads.

The vulnerable code is reachable through lock-loading paths such as `dav_lock_query()` / `get_locks()` when lock discovery or request validation loads locks for the resource.

## Why This Is A Real Bug

The DBM value is serialized external state, not an in-memory structure with compiler-enforced bounds. `val.dsize` is the only authoritative limit for safe reads from `val.dptr`.

The vulnerable parser used untrusted record contents to determine read lengths. If the serialized indirect key length exceeds the remaining bytes, `apr_pmemdup()` reads outside the fetched DB value. This can disclose adjacent process memory to the allocator copy or crash the request worker depending on memory layout. If the stored `int` length is negative, assignment to `apr_size_t` can also produce a very large copy length.

## Fix Requirement

Validate that enough bytes remain before every fixed-length and variable-length read from `val.dptr`.

For variable-length strings, do not use unbounded `strlen()` on DBM data; search for the terminating NUL only within `val.dsize - offset`.

Malformed or truncated lock records must be rejected as corrupt before any out-of-bounds read occurs.

## Patch Rationale

The patch adds local parser guards inside `dav_generic_load_lock_record()`:

- `dav_check_read(len)` verifies `len <= val.dsize - offset` before consuming bytes.
- `dav_corrupt_record()` frees the DBM datum and returns `DAV_ERR_LOCK_CORRUPT_DB`.
- Fixed-size fields are checked before `memcpy()` and `apr_pmemdup()`.
- Owner and authenticated-user strings are parsed with bounded `memchr()` instead of unbounded `strlen()`.
- The indirect key length is checked before copying `ip->key.dptr`.

This directly blocks the reproduced malformed indirect record because the large encoded key length fails the remaining-bytes check before `apr_pmemdup()` executes.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/dav/lock/locks.c b/modules/dav/lock/locks.c
index 0f072ec..2ea8006 100644
--- a/modules/dav/lock/locks.c
+++ b/modules/dav/lock/locks.c
@@ -589,6 +589,18 @@ static dav_error * dav_generic_load_lock_record(dav_lockdb *lockdb,
     dav_lock_discovery *dp;
     dav_lock_indirect *ip;
 
+#define dav_corrupt_record()                                            \
+    do {                                                                \
+        apr_dbm_freedatum(lockdb->info->db, val);                       \
+        return dav_new_error(p, HTTP_INTERNAL_SERVER_ERROR,              \
+                             DAV_ERR_LOCK_CORRUPT_DB, 0,                \
+                             "The lock database was found to be corrupt."); \
+    } while (0)
+#define dav_check_read(_len)                                            \
+    if ((_len) > val.dsize - offset) {                                  \
+        dav_corrupt_record();                                           \
+    }
+
     if (add_method != DAV_APPEND_LIST) {
         *direct = NULL;
         *indirect = NULL;
@@ -623,28 +635,42 @@ static dav_error * dav_generic_load_lock_record(dav_lockdb *lockdb,
             dp = apr_pcalloc(p, sizeof(*dp));
 
             /* Copy the dav_lock_discovery_fixed portion */
+            dav_check_read(sizeof(dp->f));
             memcpy(dp, val.dptr + offset, sizeof(dp->f));
             offset += sizeof(dp->f);
 
             /* Copy the lock token. */
+            dav_check_read(sizeof(*dp->locktoken));
             dp->locktoken = apr_pmemdup(p, val.dptr + offset, sizeof(*dp->locktoken));
             offset += sizeof(*dp->locktoken);
 
             /* Do we have an owner field? */
+            dav_check_read(1);
             if (*(val.dptr + offset) == '\0') {
                 ++offset;
             }
             else {
-                apr_size_t len = strlen(val.dptr + offset);
+                apr_size_t len;
+                void *eos = memchr(val.dptr + offset, '\0', val.dsize - offset);
+                if (eos == NULL) {
+                    dav_corrupt_record();
+                }
+                len = (char *)eos - (val.dptr + offset);
                 dp->owner = apr_pstrmemdup(p, val.dptr + offset, len);
                 offset += len + 1;
             }
 
+            dav_check_read(1);
             if (*(val.dptr + offset) == '\0') {
                 ++offset;
             }
             else {
-                apr_size_t len = strlen(val.dptr + offset);
+                apr_size_t len;
+                void *eos = memchr(val.dptr + offset, '\0', val.dsize - offset);
+                if (eos == NULL) {
+                    dav_corrupt_record();
+                }
+                len = (char *)eos - (val.dptr + offset);
                 dp->auth_user = apr_pstrmemdup(p, val.dptr + offset, len);
                 offset += len + 1;
             }
@@ -662,13 +688,17 @@ static dav_error * dav_generic_load_lock_record(dav_lockdb *lockdb,
             /* Create and fill a dav_lock_indirect structure */
 
             ip = apr_pcalloc(p, sizeof(*ip));
+            dav_check_read(sizeof(*ip->locktoken));
             ip->locktoken = apr_pmemdup(p, val.dptr + offset, sizeof(*ip->locktoken));
             offset += sizeof(*ip->locktoken);
+            dav_check_read(sizeof(ip->timeout));
             memcpy(&ip->timeout, val.dptr + offset, sizeof(ip->timeout));
             offset += sizeof(ip->timeout);
             /* length of datum */
+            dav_check_read(sizeof(ip->key.dsize));
             ip->key.dsize = *((int *) (val.dptr + offset));
             offset += sizeof(ip->key.dsize);
+            dav_check_read(ip->key.dsize);
             ip->key.dptr = apr_pmemdup(p, val.dptr + offset, ip->key.dsize);
             offset += ip->key.dsize;
 
@@ -698,6 +728,9 @@ static dav_error * dav_generic_load_lock_record(dav_lockdb *lockdb,
         }
     }
 
+#undef dav_check_read
+#undef dav_corrupt_record
+
     apr_dbm_freedatum(lockdb->info->db, val);
 
     /* Clean up this record if we found expired locks */
```