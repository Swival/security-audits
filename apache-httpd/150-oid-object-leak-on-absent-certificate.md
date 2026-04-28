# oid object leak on absent certificate

## Classification

resource lifecycle bug; medium severity; confidence: certain

## Affected Locations

`modules/ssl/ssl_engine_vars.c:1080`

## Summary

`ssl_ext_list()` allocates an `ASN1_OBJECT *` with `OBJ_txt2obj()` before looking up the selected certificate. If the requested certificate is absent, the function returns `NULL` before releasing the allocated OID object. Repeated `PeerExtList` evaluations on SSL connections without the selected certificate leak one OpenSSL allocation per evaluation.

## Provenance

Verified and patched from the supplied source and reproducer evidence. Finding provenance includes Swival Security Scanner: https://swival.dev

## Preconditions

- An SSL connection exists.
- The caller supplies an extension string that parses as a valid OID.
- The selected certificate is absent.
- The `PeerExtList` expression path is evaluated for a peer certificate case without a client certificate.

## Proof

`ssl_ext_list()` converts the caller-supplied extension string with:

```c
oid = OBJ_txt2obj(extension, 0);
```

On success, `oid` is owned by the function and normally released later with:

```c
ASN1_OBJECT_free(oid);
```

Immediately after allocation, the function selects the certificate:

```c
xs = peer ? SSL_get_peer_certificate(ssl) : SSL_get_certificate(ssl);
if (xs == NULL) {
    return NULL;
}
```

When `xs == NULL`, control returns before `ASN1_OBJECT_free(oid)` executes. The reproduced path confirms this is reachable through `PeerExtList` expression evaluation on TLS requests without a client certificate.

## Why This Is A Real Bug

The successful path explicitly frees `oid`, establishing that `ssl_ext_list()` owns the `ASN1_OBJECT *` returned by `OBJ_txt2obj()`. The `xs == NULL` early return bypasses that ownership cleanup. Because `PeerExtList` can be evaluated repeatedly on SSL requests without a client certificate, the leak is externally repeatable under the configured expression and causes process heap growth over time.

## Fix Requirement

Free `oid` before returning when certificate lookup fails.

## Patch Rationale

The patch adds `ASN1_OBJECT_free(oid)` in the `xs == NULL` branch. This preserves existing behavior by still returning `NULL` when no certificate is available, while matching the cleanup performed on the normal exit path.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/ssl/ssl_engine_vars.c b/modules/ssl/ssl_engine_vars.c
index 4060c0f..1b28bae 100644
--- a/modules/ssl/ssl_engine_vars.c
+++ b/modules/ssl/ssl_engine_vars.c
@@ -1072,6 +1072,7 @@ apr_array_header_t *ssl_ext_list(apr_pool_t *p, conn_rec *c, int peer,
 
     xs = peer ? SSL_get_peer_certificate(ssl) : SSL_get_certificate(ssl);
     if (xs == NULL) {
+        ASN1_OBJECT_free(oid);
         return NULL;
     }
```