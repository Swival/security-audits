# Unchecked Direct Lock Record Copy

## Classification

Memory safety, medium severity.

Confidence: certain.

## Affected Locations

`modules/dav/lock/locks.c:511`

## Summary

`dav_generic_load_lock_record` parsed raw lock database bytes without validating that enough bytes remained before fixed-size copies and NUL-terminated string scans. A truncated direct-lock record could cause an out-of-bounds read before the function reported database corruption.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- The DAV generic lock database contains a truncated direct-lock value.
- A request path loads locks for the affected resource key.
- The fetched value begins with `DAV_LOCK_DIRECT` but lacks the full fixed direct-lock payload.

## Proof

`apr_dbm_fetch` loads raw database bytes into `val` in `dav_generic_load_lock_record`. The original code checked only `!val.dsize` and then looped while `offset < val.dsize`.

For a one-byte value such as `{ 0x01 }`:

- The loop accepts the record because `offset < val.dsize`.
- The tag byte is consumed as `DAV_LOCK_DIRECT`.
- `offset` advances to the end of the datum.
- The direct-lock branch executes `memcpy(dp, val.dptr + offset, sizeof(dp->f))` without checking that `sizeof(dp->f)` bytes remain.
- The read starts past the fetched datum.

The same parser also performed unchecked direct-token copies, unchecked owner/auth-user dereferences, and unbounded `strlen` scans over DBM-supplied bytes.

Reachable callers include:

- `dav_generic_get_locks`
- `dav_generic_find_lock`
- `dav_generic_append_locks`
- `dav_generic_remove_lock`
- `dav_generic_refresh_locks`

## Why This Is A Real Bug

The lock database is treated as serialized binary input, but DBM values can be truncated or corrupted. The parser must reject malformed records before reading their fields.

The original parser returned corruption errors for unknown tags, but not for incomplete known records. Therefore a malformed `DAV_LOCK_DIRECT` value could trigger undefined behavior in an HTTP request path before any corrupt-record handling ran. The likely practical impact is worker crash or denial of service.

## Fix Requirement

Validate `val.dsize - offset` before every fixed-size copy, every scalar read, and every variable-length copy. Replace unbounded `strlen` over DBM data with bounded NUL searches inside the remaining datum. On malformed data, free the DBM datum and return `DAV_ERR_LOCK_CORRUPT_DB`.

## Patch Rationale

The patch adds explicit remaining-length checks before:

- Copying `dav_lock_discovery_fixed`.
- Copying direct lock tokens.
- Reading direct owner and auth-user strings.
- Copying indirect lock tokens.
- Copying indirect timeout values.
- Reading indirect key sizes.
- Copying indirect keys.

It also replaces direct-record `strlen` calls with bounded `memchr` searches constrained by `val.dsize - offset`, preventing scans past the fetched datum when strings are unterminated.

The indirect key-size read is changed from an unaligned pointer cast to `memcpy`, avoiding undefined behavior on architectures that require aligned integer access.

All malformed-record paths now share a single `corrupt` label that frees `val` and returns a corruption error.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/dav/lock/locks.c b/modules/dav/lock/locks.c
index 0f072ec..e8f5534 100644
--- a/modules/dav/lock/locks.c
+++ b/modules/dav/lock/locks.c
@@ -623,28 +623,54 @@ static dav_error * dav_generic_load_lock_record(dav_lockdb *lockdb,
             dp = apr_pcalloc(p, sizeof(*dp));
 
             /* Copy the dav_lock_discovery_fixed portion */
+            if (val.dsize - offset < sizeof(dp->f)) {
+                goto corrupt;
+            }
             memcpy(dp, val.dptr + offset, sizeof(dp->f));
             offset += sizeof(dp->f);
 
             /* Copy the lock token. */
+            if (val.dsize - offset < sizeof(*dp->locktoken)) {
+                goto corrupt;
+            }
             dp->locktoken = apr_pmemdup(p, val.dptr + offset, sizeof(*dp->locktoken));
             offset += sizeof(*dp->locktoken);
 
             /* Do we have an owner field? */
+            if (offset == val.dsize) {
+                goto corrupt;
+            }
             if (*(val.dptr + offset) == '\0') {
                 ++offset;
             }
             else {
-                apr_size_t len = strlen(val.dptr + offset);
+                const char *nul = memchr(val.dptr + offset, '\0',
+                                         val.dsize - offset);
+                apr_size_t len;
+
+                if (nul == NULL) {
+                    goto corrupt;
+                }
+                len = nul - (val.dptr + offset);
                 dp->owner = apr_pstrmemdup(p, val.dptr + offset, len);
                 offset += len + 1;
             }
 
+            if (offset == val.dsize) {
+                goto corrupt;
+            }
             if (*(val.dptr + offset) == '\0') {
                 ++offset;
             }
             else {
-                apr_size_t len = strlen(val.dptr + offset);
+                const char *nul = memchr(val.dptr + offset, '\0',
+                                         val.dsize - offset);
+                apr_size_t len;
+
+                if (nul == NULL) {
+                    goto corrupt;
+                }
+                len = nul - (val.dptr + offset);
                 dp->auth_user = apr_pstrmemdup(p, val.dptr + offset, len);
                 offset += len + 1;
             }
@@ -662,13 +688,25 @@ static dav_error * dav_generic_load_lock_record(dav_lockdb *lockdb,
             /* Create and fill a dav_lock_indirect structure */
 
             ip = apr_pcalloc(p, sizeof(*ip));
+            if (val.dsize - offset < sizeof(*ip->locktoken)) {
+                goto corrupt;
+            }
             ip->locktoken = apr_pmemdup(p, val.dptr + offset, sizeof(*ip->locktoken));
             offset += sizeof(*ip->locktoken);
+            if (val.dsize - offset < sizeof(ip->timeout)) {
+                goto corrupt;
+            }
             memcpy(&ip->timeout, val.dptr + offset, sizeof(ip->timeout));
             offset += sizeof(ip->timeout);
             /* length of datum */
-            ip->key.dsize = *((int *) (val.dptr + offset));
+            if (val.dsize - offset < sizeof(ip->key.dsize)) {
+                goto corrupt;
+            }
+            memcpy(&ip->key.dsize, val.dptr + offset, sizeof(ip->key.dsize));
             offset += sizeof(ip->key.dsize);
+            if (ip->key.dsize > val.dsize - offset) {
+                goto corrupt;
+            }
             ip->key.dptr = apr_pmemdup(p, val.dptr + offset, ip->key.dsize);
             offset += ip->key.dsize;
 
@@ -683,18 +721,9 @@ static dav_error * dav_generic_load_lock_record(dav_lockdb *lockdb,
             break;
 
         default:
-            apr_dbm_freedatum(lockdb->info->db, val);
-
             /* ### should use a computed_desc and insert corrupt token data */
             --offset;
-            return dav_new_error(p,
-                                 HTTP_INTERNAL_SERVER_ERROR,
-                                 DAV_ERR_LOCK_CORRUPT_DB, 0,
-                                 apr_psprintf(p,
-                                             "The lock database was found to "
-                                             "be corrupt. offset %"
-                                             APR_SIZE_T_FMT ", c=%02x",
-                                             offset, val.dptr[offset]));
+            goto corrupt;
         }
     }
 
@@ -710,6 +739,16 @@ static dav_error * dav_generic_load_lock_record(dav_lockdb *lockdb,
     }
 
     return NULL;
+
+corrupt:
+    apr_dbm_freedatum(lockdb->info->db, val);
+    return dav_new_error(p,
+                         HTTP_INTERNAL_SERVER_ERROR,
+                         DAV_ERR_LOCK_CORRUPT_DB, 0,
+                         apr_psprintf(p,
+                                      "The lock database was found to be "
+                                      "corrupt. offset %" APR_SIZE_T_FMT,
+                                      offset));
 }
 
 /* resolve <indirect>, returning <*direct> */
```