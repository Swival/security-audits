# authz dereference after failed retrieval

## Classification

Memory safety, medium severity.

## Affected Locations

`modules/md/md_acme_order.c:456`

## Summary

`md_acme_order_start_challenges()` dereferenced `authz->domain` immediately after `md_acme_authz_retrieve()` returned failure. On retrieval failure, `authz` is not guaranteed to reference a valid authorization object and may be `NULL`, causing an invalid pointer dereference during ACME challenge startup.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- `md_acme_order_start_challenges()` is processing an order authorization URL.
- `md_acme_authz_retrieve(acme, p, url, &authz)` returns a non-success status.
- The retrieval failure occurs before assigning a valid `authz` object to the output pointer.

## Proof

`authz` is declared in `md_acme_order_start_challenges()` before the authorization retrieval loop.

On each authorization URL, the function calls:

```c
md_acme_authz_retrieve(acme, p, url, &authz)
```

If that call fails, the failure branch previously logged:

```c
md_log_perror(..., "%s: check authz for %s", md->name, authz->domain);
```

The reproducer confirmed that `md_acme_authz_retrieve()` can return failure with `authz == NULL`, including when HTTP/JSON retrieval fails or when the returned authorization state remains unknown and `APR_EINVAL` is produced. The failed branch therefore evaluates `authz->domain` before any valid assignment is guaranteed.

Reachability is confirmed through the ACMEv2 renewal flow: `md_acme_order_start_challenges()` is called after an order is available, while starting challenges for order authorization URLs.

## Why This Is A Real Bug

The dereference happens before entering `md_log_perror()`, so this is not only a logging-quality issue. A failed authorization retrieval can produce a null output pointer, and the caller immediately dereferences it in the error path. This can crash the local process during managed-domain certificate renewal or challenge startup, producing denial of service.

## Fix Requirement

Do not dereference `authz` after `md_acme_authz_retrieve()` fails unless the pointer has been proven valid. The error log should use data already known to be valid, such as the authorization URL, or explicitly guard `authz` before accessing fields.

## Patch Rationale

The patch replaces the unsafe `authz->domain` logging argument with `url`, which is the authorization URL already loaded from `order->authz_urls` before the retrieval call. This preserves useful diagnostic context while avoiding any dependency on a successfully populated `authz` object in the failure path.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/md/md_acme_order.c b/modules/md/md_acme_order.c
index 22d84a2..5d932e5 100644
--- a/modules/md/md_acme_order.c
+++ b/modules/md/md_acme_order.c
@@ -459,8 +459,8 @@ apr_status_t md_acme_order_start_challenges(md_acme_order_t *order, md_acme_t *a
         md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, "%s: check AUTHZ at %s", md->name, url);
         
         if (APR_SUCCESS != (rv = md_acme_authz_retrieve(acme, p, url, &authz))) {
-            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, "%s: check authz for %s",
-                          md->name, authz->domain);
+            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, "%s: check authz at %s",
+                          md->name, url);
             goto leave;
         }
```