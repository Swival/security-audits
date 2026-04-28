# Unbounded Namespace ID Traversal

## Classification

Memory safety, medium severity.

## Affected Locations

`modules/dav/fs/dbm.c:701`

## Summary

Property DBM keys containing a namespace ID greater than or equal to `db->ns_count` cause `dav_get_ns_table_uri()` to walk past the namespace table and call `strlen()` on out-of-bounds memory during property enumeration.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

A WebDAV property DB contains a non-empty namespace key whose parsed namespace ID is outside the valid table range:

`id < 0 || id >= db->ns_count`

Normal `PROPPATCH` storage appears to generate bounded IDs through `dav_build_key()`, so this requires a corrupted or externally modified `.DAV` property DB.

## Proof

DBM keys originate from `apr_dbm_firstkey()` and `apr_dbm_nextkey()` and are stored in `db->iter`.

During enumeration, `dav_set_name()` parses non-`:name` keys with:

```c
int id = atoi(s);
pname->ns = dav_get_ns_table_uri(db, id);
```

`dav_get_ns_table_uri()` then advances through the packed namespace table without validating `ns_id`:

```c
while (ns_id--)
    p += strlen(p) + 1;
```

If `ns_id >= db->ns_count`, `p` moves past the valid namespace table and `strlen(p)` reads out of bounds.

The helper logic was reproduced under ASan with `ns_count == 1` and `ns_id == 2`, producing a heap-buffer-overflow in `strlen()`.

## Why This Is A Real Bug

The namespace table has an explicit bound, `db->ns_count`, but untrusted persisted DBM key data is used as an index without checking that bound.

A malformed key can therefore cause an out-of-bounds read during property enumeration. In a server worker, this can crash the process and produce a denial of service.

## Fix Requirement

Reject parsed namespace IDs unless they satisfy:

```c
0 <= id && id < db->ns_count
```

Invalid keys must not be passed to `dav_get_ns_table_uri()`.

## Patch Rationale

The patch adds the missing range check immediately after parsing the namespace ID in `dav_set_name()`.

For invalid IDs, it sets both output fields to `NULL` and returns before any namespace table traversal occurs. This preserves valid-key behavior while preventing `dav_get_ns_table_uri()` from receiving an out-of-range index.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/dav/fs/dbm.c b/modules/dav/fs/dbm.c
index 39ab4ad..01de22c 100644
--- a/modules/dav/fs/dbm.c
+++ b/modules/dav/fs/dbm.c
@@ -696,6 +696,11 @@ static void dav_set_name(dav_db *db, dav_prop_name *pname)
     else {
         int id = atoi(s);
 
+        if (id < 0 || id >= db->ns_count) {
+            pname->ns = pname->name = NULL;
+            return;
+        }
+
         pname->ns = dav_get_ns_table_uri(db, id);
         if (s[1] == ':') {
             pname->name = s + 2;
```