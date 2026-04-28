# Null Request State Dereference In ldap-search

## Classification

Memory safety, high severity, worker crash / denial of service.

Confidence: certain.

## Affected Locations

`modules/aaa/mod_authnz_ldap.c:1068`

Primary vulnerable flow in affected source:

`modules/aaa/mod_authnz_ldap.c:1495`

## Summary

`ldapsearch_check_authorization` reads per-request LDAP state with `ap_get_module_config(r->request_config, &authnz_ldap_module)` into `req`, but unlike other LDAP authorization handlers it does not create the request state when it is absent.

When `Require ldap-search ...` authorization runs without prior `mod_authnz_ldap` authentication state, `req` can be `NULL`. On a successful LDAP search, the handler passes `&(req->vals)` to `util_ldap_cache_getuserdn` and later assigns `req->dn = dn`, dereferencing the null pointer and crashing the worker.

## Provenance

Verified and patched from supplied source and reproducer evidence.

Scanner provenance: [Swival Security Scanner](https://swival.dev)

## Preconditions

- `ldap-search` authorization is configured, for example with `Require ldap-search ...`.
- Authorization reaches `ldapsearch_check_authorization` through normal authz provider dispatch.
- No prior `mod_authnz_ldap` authentication state exists in `r->request_config`.
- `AuthLDAPURL` and LDAP host configuration are valid.
- The `Require ldap-search` expression is non-empty.
- The LDAP search returns exactly one DN.

## Proof

- `ldapsearch_check_authorization` obtains request state from `ap_get_module_config(r->request_config, &authnz_ldap_module)` into `req`.
- `authn_ldap_check_password` creates this state during LDAP authentication, but authorization can run after another authentication provider or without LDAP authn state.
- Other LDAP authz handlers allocate `req` when it is missing; `ldap-search` does not.
- On the non-empty filter path, `ldap-search` calls:

```c
result = util_ldap_cache_getuserdn(r, ldc, sec->url, sec->basedn,
     sec->scope, sec->attributes, t, &dn, &(req->vals));
```

- If `req == NULL`, `&(req->vals)` is derived from a null base pointer.
- If LDAP URL attributes are configured, `modules/ldap/util_ldap.c:2130` can write through that output pointer.
- Even without attributes, the success path assigns:

```c
req->dn = dn;
```

- That assignment dereferences `NULL` when the LDAP search succeeds and returns a DN.

## Why This Is A Real Bug

The vulnerable provider is registered normally as `ldap-search`, so a configured `Require ldap-search ...` reaches this handler through standard authorization processing.

The missing allocation is inconsistent with the neighboring LDAP authorization handlers, which explicitly handle absent request state for cases where authentication was performed by another module. Therefore `req == NULL` is an expected runtime state, not an impossible invariant.

A normal request to a protected location can satisfy the trigger conditions and cause a null pointer dereference in the worker process, producing a denial of service.

## Fix Requirement

Before `ldapsearch_check_authorization` passes `&(req->vals)` or assigns fields through `req`, it must ensure that `req` is non-null.

Acceptable fixes are:

- allocate an `authn_ldap_request_t` from `r->pool` when `req == NULL`; or
- deny authorization before any dereference when `req == NULL`.

## Patch Rationale

The patch allocates request state in `ldapsearch_check_authorization` immediately before the LDAP search path needs `req->vals`.

This mirrors the defensive pattern already used by the other LDAP authorization handlers and preserves existing successful `ldap-search` behavior. It prevents both the output-parameter null-base dereference and the later `req->dn = dn` dereference.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/aaa/mod_authnz_ldap.c b/modules/aaa/mod_authnz_ldap.c
index d5b8b80..5437f2f 100644
--- a/modules/aaa/mod_authnz_ldap.c
+++ b/modules/aaa/mod_authnz_ldap.c
@@ -1495,6 +1495,11 @@ static authz_status ldapsearch_check_authorization(request_rec *r,
         ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02630)
                       "auth_ldap authorize: checking filter %s", t);
 
+        if (!req) {
+            req = (authn_ldap_request_t *)apr_pcalloc(r->pool,
+                sizeof(authn_ldap_request_t));
+        }
+
         /* Search for the user DN */
         result = util_ldap_cache_getuserdn(r, ldc, sec->url, sec->basedn,
              sec->scope, sec->attributes, t, &dn, &(req->vals));
```