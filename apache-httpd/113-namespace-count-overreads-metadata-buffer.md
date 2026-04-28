# namespace count overreads metadata buffer

## Classification

Validation gap, medium severity.

## Affected Locations

`modules/dav/fs/dbm.c:498`

## Summary

A malformed WebDAV property DB `METADATA` record can set an excessive namespace count. `dav_propdb_open()` trusts that count and walks namespace strings with `strlen()` without proving each entry is contained inside the copied DBM value, allowing an out-of-bounds read.

## Provenance

Verified from the provided source, reproducer, and patch. Initially reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

A property DB contains a malformed `METADATA` record with an excessive `ns_count`.

## Proof

`dav_propdb_open()` fetches the `METADATA` value from DBM, copies exactly `value.dsize` bytes into `db->ns_table.buf`, then copies the fixed metadata header and assigns:

```c
db->ns_count = ntohs(m.ns_count);
```

The original code then iterates `db->ns_count` entries:

```c
for (ns = 0, uri = db->ns_table.buf + sizeof(dav_propdb_metadata);
     ns++ < db->ns_count;
     uri += strlen(uri) + 1) {
```

No check ensures that `value.dsize` is at least `sizeof(dav_propdb_metadata)`, that `uri` is still within `db->ns_table.buf`, or that each namespace string has a NUL terminator before the end of the copied value.

The reproducer confirms that a 256-byte `METADATA` value with `ns_count = htons(1)` and no NUL after the metadata header causes `strlen(uri)` to read past the allocated namespace buffer, producing an ASan heap-buffer-overflow.

## Why This Is A Real Bug

The DBM value is attacker-relevant persistent input once the property database is malformed. The code treats the record as trusted internal structure, but `ns_count` and the string table are both loaded directly from storage. If `ns_count` exceeds the number of actual NUL-terminated entries, `strlen()` advances beyond `db->ns_table.cur_len`.

Impact is concrete: the process may crash from an out-of-bounds read, or if a later NUL is found, bytes from adjacent allocation data may be copied into the URI hash entry.

## Fix Requirement

Validate the `METADATA` record before trusting `ns_count`:

- Require `value.dsize >= sizeof(dav_propdb_metadata)`.
- Bound namespace parsing to the copied metadata buffer length.
- Require each namespace entry to contain a NUL terminator before the buffer end.
- Reject corrupt metadata before building `db->uri_index`.

## Patch Rationale

The patch adds an `end` pointer for `db->ns_table.buf + db->ns_table.cur_len` and rejects short metadata records before copying the header. During namespace index construction, it checks:

```c
if (uri >= end || memchr(uri, '\0', end - uri) == NULL)
```

This proves `strlen(uri)` and `apr_pstrdup(pool, uri)` operate only on strings fully contained within the copied DBM value. It also frees the DBM datum and closes the database on corrupt metadata before returning an internal error.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/dav/fs/dbm.c b/modules/dav/fs/dbm.c
index 39ab4ad..c5f84ca 100644
--- a/modules/dav/fs/dbm.c
+++ b/modules/dav/fs/dbm.c
@@ -473,6 +473,17 @@ static dav_error * dav_propdb_open(apr_pool_t *pool,
         dav_propdb_metadata m;
         long ns;
         const char *uri;
+        const char *end;
+
+        if (value.dsize < sizeof(m)) {
+            dav_dbm_freedatum(db, value);
+            dav_dbm_close(db);
+
+            return dav_new_error(pool, HTTP_INTERNAL_SERVER_ERROR,
+                                 DAV_ERR_PROP_BAD_MAJOR, 0,
+                                 "Prop database metadata is corrupt "
+                                 "and cannot be used.");
+        }
 
         dav_set_bufsize(pool, &db->ns_table, value.dsize);
         memcpy(db->ns_table.buf, value.dptr, value.dsize);
@@ -488,19 +499,30 @@ static dav_error * dav_propdb_open(apr_pool_t *pool,
         }
         db->version = m.minor;
         db->ns_count = ntohs(m.ns_count);
-
-        dav_dbm_freedatum(db, value);
+        end = db->ns_table.buf + db->ns_table.cur_len;
 
         /* create db->uri_index */
         for (ns = 0, uri = db->ns_table.buf + sizeof(dav_propdb_metadata);
              ns++ < db->ns_count;
              uri += strlen(uri) + 1) {
 
+            if (uri >= end || memchr(uri, '\0', end - uri) == NULL) {
+                dav_dbm_freedatum(db, value);
+                dav_dbm_close(db);
+
+                return dav_new_error(pool, HTTP_INTERNAL_SERVER_ERROR,
+                                     DAV_ERR_PROP_BAD_MAJOR, 0,
+                                     "Prop database metadata is corrupt "
+                                     "and cannot be used.");
+            }
+
             /* we must copy the key, in case ns_table.buf moves */
             apr_hash_set(db->uri_index,
                          apr_pstrdup(pool, uri), APR_HASH_KEY_STRING,
                          (void *)ns);
         }
+
+        dav_dbm_freedatum(db, value);
     }
 
     *pdb = db;
```