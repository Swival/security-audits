# Solaris group ACL denial falls through to other

## Classification

security_control_failure; severity high; confidence certain.

## Affected Locations

`modules/mod_facl.c:888`

## Summary

`check_solaris_facl()` failed open for Solaris POSIX ACL group denials. When an authenticated FTP user matched `GROUP_OBJ` or a named `GROUP` ACL entry that lacked the requested permission, the function did not record that denying group match. It then fell through to `OTHER_OBJ`, allowing the operation if `other` granted the requested mode.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- Solaris POSIX ACL build.
- `FACLEngine` enabled.
- FTP operation reaches `facl_fsio_access()` or `facl_fsio_faccess()`.
- User is not the file owner and does not match a granting named user ACL entry.
- User primary or supplementary group matches `st_gid` or a named `GROUP` ACL entry.
- Matching group ACL lacks the requested mode.
- `OTHER_OBJ` grants the requested mode.

## Proof

Concrete failing case:

- `uid != st_uid`
- `gid == st_gid`
- requested `mode = R_OK`
- `GROUP_OBJ.a_perm = 0`
- `OTHER_OBJ.a_perm = R_OK`

In the vulnerable Solaris path:

- The primary group match is tested in `check_solaris_facl()`.
- Because `acl_group_entry.a_perm & mode` is false, no access entry is selected.
- `have_access_entry` remains false.
- Step 5 explicitly says matching group denial must deny access, but the implementation only had `/* XXX implement this condition properly */`.
- Step 6 then selects `acl_other_entry`.
- The final `OTHER_OBJ` access check succeeds because `OTHER_OBJ.a_perm & mode` is true.
- The function returns `0`, authorizing an operation the ACL group entry denied.

The same fallthrough existed for supplementary group matches and named `GROUP` ACL matches.

## Why This Is A Real Bug

The function’s own ACL selection algorithm states that if any user group matches the group owner entry or a named group entry, but no matching group entry contains the requested permissions, access is denied. The implementation violated that rule by treating the absence of a granting group entry as if no group matched at all, allowing `OTHER_OBJ` to decide access. Since `facl_fsio_access()` and `facl_fsio_faccess()` use this decision for FTP file operations, an authenticated FTP user in a denied group could perform unauthorized file operations whenever `other` was more permissive.

## Fix Requirement

Track whether a primary or supplementary group matched `GROUP_OBJ` or named `GROUP` but lacked the requested permission, and return `EACCES` before the `OTHER_OBJ` fallback when no granting ACL entry was selected.

## Patch Rationale

The patch adds `have_matching_denied_group` to `check_solaris_facl()` and sets it whenever:

- primary `gid` matches `st_gid` but `GROUP_OBJ` lacks `mode`;
- supplementary group matches `st_gid` but `GROUP_OBJ` lacks `mode`;
- primary `gid` matches a named `GROUP` entry but that entry lacks `mode`;
- supplementary group matches a named `GROUP` entry but that entry lacks `mode`.

Before selecting `OTHER_OBJ`, the patch checks:

```c
if (!have_access_entry &&
    have_matching_denied_group) {
  destroy_pool(acl_pool);

  pr_trace_msg(trace_channel, 3,
    "returning EACCES for path '%s', user ID %s", path,
    pr_uid2str(NULL, uid));
  errno = EACCES;
  return -1;
}
```

This implements the documented step 5 denial and prevents group-matching ACL denials from falling through to `other`.

## Residual Risk

None

## Patch

`016-solaris-group-acl-denial-falls-through-to-other.patch`

```diff
diff --git a/modules/mod_facl.c b/modules/mod_facl.c
index c6099d22f..a8be44d9e 100644
--- a/modules/mod_facl.c
+++ b/modules/mod_facl.c
@@ -649,7 +649,8 @@ static int check_solaris_facl(pool *p, const char *path, int mode, void *acl,
     int nents, struct stat *st, uid_t uid, gid_t gid,
     array_header *suppl_gids) {
   register unsigned int i;
-  int have_access_entry = FALSE, have_mask_entry = FALSE, idx, res = -1;
+  int have_access_entry = FALSE, have_mask_entry = FALSE;
+  int have_matching_denied_group = FALSE, idx, res = -1;
   pool *acl_pool;
   aclent_t *acls = acl;
   aclent_t ae;
@@ -811,6 +812,9 @@ static int check_solaris_facl(pool *p, const char *path, int mode, void *acl,
       pr_trace_msg(trace_channel, 10,
         "primary group ID %s matches ACL owner group ID",
         pr_gid2str(NULL, gid));
+
+    } else {
+      have_matching_denied_group = TRUE;
     }
   }
 
@@ -832,6 +836,9 @@ static int check_solaris_facl(pool *p, const char *path, int mode, void *acl,
             pr_gid2str(NULL, suppl_gid));
 
           break;
+
+        } else {
+          have_matching_denied_group = TRUE;
         }
       }
     }
@@ -860,6 +867,9 @@ static int check_solaris_facl(pool *p, const char *path, int mode, void *acl,
           pr_gid2str(NULL, gid));
 
         break;
+
+      } else {
+        have_matching_denied_group = TRUE;
       }
     }
 
@@ -883,6 +893,9 @@ static int check_solaris_facl(pool *p, const char *path, int mode, void *acl,
               pr_gid2str(NULL, suppl_gid));
 
             break;
+
+          } else {
+            have_matching_denied_group = TRUE;
           }
         }
       }
@@ -895,7 +908,16 @@ static int check_solaris_facl(pool *p, const char *path, int mode, void *acl,
    *    the requested permissions, access is denied.
    */
 
-  /* XXX implement this condition properly */
+  if (!have_access_entry &&
+      have_matching_denied_group) {
+    destroy_pool(acl_pool);
+
+    pr_trace_msg(trace_channel, 3,
+      "returning EACCES for path '%s', user ID %s", path,
+      pr_uid2str(NULL, uid));
+    errno = EACCES;
+    return -1;
+  }
 
   /* 6. If not matched above, the other entry determines access.
    */
```