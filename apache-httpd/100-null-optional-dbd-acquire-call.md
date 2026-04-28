# null optional DBD acquire call

## Classification

Memory safety, denial of service. Severity: medium. Confidence: certain.

## Affected Locations

`modules/aaa/mod_authn_dbd.c:203`

## Summary

`authn_dbd_realm()` calls the optional DBD acquire function pointer before validating that a realm query was configured. If the `dbd` digest auth provider is configured without any parsed `AuthDBDUserRealmQuery` or `AuthDBDUserPWQuery`, `authn_dbd_acquire_fn` remains `NULL`. A digest authentication request can then trigger a NULL function-pointer call and crash the request-handling process.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- Digest authentication is configured with `AuthDigestProvider dbd`.
- No `AuthDBDUserRealmQuery` directive is parsed for the applicable configuration.
- No `AuthDBDUserPWQuery` directive has been parsed earlier in a way that would call `authn_dbd_prepare()` and initialize `authn_dbd_acquire_fn`.
- A request reaches the registered DBD realm provider `authn_dbd_realm()`.

## Proof

A practical vulnerable configuration is:

```apache
AuthType Digest
AuthName "realm"
AuthDigestProvider dbd
Require valid-user
# no AuthDBDUserRealmQuery
# no AuthDBDUserPWQuery
```

With a syntactically valid Digest `Authorization` header whose realm matches `AuthName`, the request reaches digest `get_hash()`, then `provider->get_realm_hash()`, then `authn_dbd_realm()`.

In the vulnerable code, `authn_dbd_realm()` obtains the per-directory config and immediately evaluates:

```c
ap_dbd_t *dbd = authn_dbd_acquire_fn(r);
```

Because no `AuthDBD*Query` directive ran, `authn_dbd_prepare()` never retrieved `ap_dbd_acquire`, so `authn_dbd_acquire_fn` is still `NULL`. The call therefore dereferences a NULL function pointer before the later `conf->realm == NULL` check can report the missing `AuthDBDUserRealmQuery`.

The digest response value does not need to be correct because provider lookup occurs before digest comparison.

## Why This Is A Real Bug

The code already intends to reject missing realm-query configuration with `APLOGNO(01659)` and `AUTH_GENERAL_ERROR`, but the rejection occurs after the optional function pointer is called. The optional pointer is initialized only as a side effect of parsing an `AuthDBDUserPWQuery` or `AuthDBDUserRealmQuery` directive. In the reproduced configuration, that side effect never happens, making the request path capable of invoking a NULL function pointer.

This is request-triggered and does not require a valid password or successful digest authentication.

## Fix Requirement

Validate `conf->realm` before calling `authn_dbd_acquire_fn`, or otherwise explicitly check that `authn_dbd_acquire_fn` is non-NULL before invocation.

## Patch Rationale

The patch moves the existing `conf->realm == NULL` validation ahead of the DBD connection acquisition:

```diff
-    ap_dbd_t *dbd = authn_dbd_acquire_fn(r);
+    ap_dbd_t *dbd;
+    if (conf->realm == NULL) {
+        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01659)
+                      "No AuthDBDUserRealmQuery has been specified");
+        return AUTH_GENERAL_ERROR;
+    }
+    dbd = authn_dbd_acquire_fn(r);
```

This preserves the existing error handling and log message for a missing `AuthDBDUserRealmQuery`, while ensuring the function does not call the optional DBD acquire hook when no realm query was configured.

## Residual Risk

None

## Patch

`100-null-optional-dbd-acquire-call.patch`

```diff
diff --git a/modules/aaa/mod_authn_dbd.c b/modules/aaa/mod_authn_dbd.c
index 08e5993..c267487 100644
--- a/modules/aaa/mod_authn_dbd.c
+++ b/modules/aaa/mod_authn_dbd.c
@@ -200,18 +200,19 @@ static authn_status authn_dbd_realm(request_rec *r, const char *user,
 
     authn_dbd_conf *conf = ap_get_module_config(r->per_dir_config,
                                                 &authn_dbd_module);
-    ap_dbd_t *dbd = authn_dbd_acquire_fn(r);
+    ap_dbd_t *dbd;
+    if (conf->realm == NULL) {
+        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01659)
+                      "No AuthDBDUserRealmQuery has been specified");
+        return AUTH_GENERAL_ERROR;
+    }
+    dbd = authn_dbd_acquire_fn(r);
     if (dbd == NULL) {
         ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01658)
                       "Failed to acquire database connection to look up "
                       "user '%s:%s'", user, realm);
         return AUTH_GENERAL_ERROR;
     }
-    if (conf->realm == NULL) {
-        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01659)
-                      "No AuthDBDUserRealmQuery has been specified");
-        return AUTH_GENERAL_ERROR;
-    }
     statement = apr_hash_get(dbd->prepared, conf->realm, APR_HASH_KEY_STRING);
     if (statement == NULL) {
         ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01660)
```