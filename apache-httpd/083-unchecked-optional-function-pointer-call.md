# unchecked optional function pointer call

## Classification

Memory safety, denial of service. Severity: medium. Confidence: certain.

## Affected Locations

`modules/aaa/mod_authz_dbm.c:247`

## Summary

The `dbm-file-group` authorization provider calls the optional `authz_owner_get_file_group` function pointer without first verifying that the optional function was provided. If `mod_authz_owner` is not loaded or otherwise does not export the optional function, the pointer remains `NULL`. A request that reaches `dbmfilegroup_check_authorization` after a successful DBM group lookup dereferences the `NULL` function pointer and crashes the server worker/process.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

## Preconditions

- The `dbm-file-group` authorization provider is used.
- `mod_authz_owner` is not loaded, or the optional `authz_owner_get_file_group` function is otherwise unavailable.
- `AuthDBMGroupFile` is configured and readable.
- The DBM group file contains a matching entry for the authenticated user, so execution reaches the file-group comparison path.

## Proof

`modules/aaa/mod_authz_dbm.c` registers the `dbm-file-group` provider unconditionally.

`authz_dbm_getfns` assigns:

```c
authz_owner_get_file_group = APR_RETRIEVE_OPTIONAL_FN(authz_owner_get_file_group);
```

`APR_RETRIEVE_OPTIONAL_FN` may return `NULL` when the optional provider is unavailable.

During authorization, `dbmfilegroup_check_authorization` performs a DBM lookup. If the lookup succeeds and returns a non-`NULL` group list, execution reaches:

```c
filegroup = authz_owner_get_file_group(r);
```

There is no intervening `NULL` check. With `authz_owner_get_file_group == NULL`, this is a request-triggerable `NULL` function pointer call.

Practical trigger:

- Load and use `mod_authz_dbm`.
- Configure `Require dbm-file-group`.
- Configure a valid `AuthDBMGroupFile` containing the authenticated user.
- Do not load/provide `mod_authz_owner`.
- Send a request that reaches authorization for that resource.

Result: the worker/server process crashes.

## Why This Is A Real Bug

The optional function retrieval API explicitly permits absence of the provider function. The code stores the retrieved optional function in a global function pointer but treats it as mandatory later. The `dbm-file-group` provider is registered regardless of whether the optional owner provider exists, so configuration can legitimately route requests into this code path with the pointer unset. Because the call occurs after attacker-triggerable request authorization flow, the impact is a request-triggerable denial of service under the stated configuration.

## Fix Requirement

Before calling `authz_owner_get_file_group`, check whether the function pointer is non-`NULL`. If it is unavailable, authorization must fail safely instead of dereferencing the pointer.

## Patch Rationale

The patch adds a guard immediately before the optional function call:

```c
if (!authz_owner_get_file_group) {
    return AUTHZ_DENIED;
}
```

This preserves existing behavior when the optional function is available. When it is unavailable, the `dbm-file-group` requirement cannot be evaluated, so denying authorization is the safe outcome. The patch prevents the `NULL` function pointer dereference without changing DBM lookup behavior or successful authorization semantics.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/aaa/mod_authz_dbm.c b/modules/aaa/mod_authz_dbm.c
index f11de68..2853813 100644
--- a/modules/aaa/mod_authz_dbm.c
+++ b/modules/aaa/mod_authz_dbm.c
@@ -276,6 +276,10 @@ static authz_status dbmfilegroup_check_authorization(request_rec *r,
         return AUTHZ_DENIED;
     }
 
+    if (!authz_owner_get_file_group) {
+        return AUTHZ_DENIED;
+    }
+
     filegroup = authz_owner_get_file_group(r);
 
     if (filegroup) {
```