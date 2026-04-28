# null optional DBD acquire call

## Classification

Memory safety, medium severity. Confidence: certain.

## Affected Locations

`modules/aaa/mod_authn_dbd.c:107`

## Summary

`authn_dbd_password()` calls the optional `authn_dbd_acquire_fn` function pointer before validating that `AuthDBDUserPWQuery` configured the DBD password provider. If the DBD password provider is enabled without an `AuthDBDUserPWQuery` or other DBD prepare directive, `authn_dbd_acquire_fn` remains `NULL`, and the request path dereferences a NULL function pointer, crashing the serving process.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- The `dbd` password provider is enabled.
- `AuthDBDUserPWQuery` is omitted.
- No other `AuthDBD` prepare directive invokes `authn_dbd_prepare`.
- A request reaches the registered DBD password provider.

## Proof

`authn_dbd_acquire_fn` is initialized to `NULL` and is only assigned in `authn_dbd_prepare`. The prepare function is wired to `AuthDBDUserPWQuery` and `AuthDBDUserRealmQuery`; omitting both leaves the optional acquire function pointer unset.

On a Basic auth request, `mod_auth_basic` calls the provider `check_password`, reaching `authn_dbd_password()`. The vulnerable code retrieves `conf`, then immediately calls:

```c
ap_dbd_t *dbd = authn_dbd_acquire_fn(r);
```

Only after that call does it check:

```c
if (conf->user == NULL) {
    ...
}
```

With `AuthDBDUserPWQuery` omitted, the intended configuration error path is unreachable because the NULL function pointer call occurs first.

## Why This Is A Real Bug

The failure is in the request path and is triggered by a valid but incomplete authentication configuration. Instead of returning `AUTH_GENERAL_ERROR` with the existing `"No AuthDBDUserPWQuery has been specified"` log message, the process attempts to call a NULL optional function pointer. That is a memory safety fault and can crash the worker handling the request.

## Fix Requirement

`authn_dbd_password()` must validate `conf->user` before any DBD acquisition attempt, and it must not call `authn_dbd_acquire_fn` unless the optional function pointer is non-NULL.

## Patch Rationale

The patch moves the `conf->user == NULL` validation before the acquire call, making the existing configuration error reachable before any optional DBD function is used. It also changes acquisition to:

```c
dbd = authn_dbd_acquire_fn ? authn_dbd_acquire_fn(r) : NULL;
```

This prevents a NULL function pointer call even if the optional function was not retrieved. The existing `dbd == NULL` error handling remains responsible for returning `AUTH_GENERAL_ERROR` when acquisition is unavailable or fails.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/aaa/mod_authn_dbd.c b/modules/aaa/mod_authn_dbd.c
index 08e5993..5ab577c 100644
--- a/modules/aaa/mod_authn_dbd.c
+++ b/modules/aaa/mod_authn_dbd.c
@@ -101,10 +101,17 @@ static authn_status authn_dbd_password(request_rec *r, const char *user,
     apr_dbd_results_t *res = NULL;
     apr_dbd_row_t *row = NULL;
     int ret;
+    ap_dbd_t *dbd;
 
     authn_dbd_conf *conf = ap_get_module_config(r->per_dir_config,
                                                 &authn_dbd_module);
-    ap_dbd_t *dbd = authn_dbd_acquire_fn(r);
+    if (conf->user == NULL) {
+        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01654)
+                      "No AuthDBDUserPWQuery has been specified");
+        return AUTH_GENERAL_ERROR;
+    }
+
+    dbd = authn_dbd_acquire_fn ? authn_dbd_acquire_fn(r) : NULL;
     if (dbd == NULL) {
         ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01653)
                       "Failed to acquire database connection to look up "
@@ -112,12 +119,6 @@ static authn_status authn_dbd_password(request_rec *r, const char *user,
         return AUTH_GENERAL_ERROR;
     }
 
-    if (conf->user == NULL) {
-        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01654)
-                      "No AuthDBDUserPWQuery has been specified");
-        return AUTH_GENERAL_ERROR;
-    }
-
     statement = apr_hash_get(dbd->prepared, conf->user, APR_HASH_KEY_STRING);
     if (statement == NULL) {
         ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01655)
```