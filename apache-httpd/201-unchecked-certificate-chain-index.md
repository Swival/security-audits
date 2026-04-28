# unchecked certificate chain index

## Classification

Validation gap, medium severity.

## Affected Locations

`modules/md/md_status.c:206`

## Summary

`get_staging_certs_json()` reads certificate index 0 from a chain returned by `md_pubcert_load()` without verifying that the chain exists and contains at least one element. If `md_pubcert_load()` succeeds with an empty certificate chain, `APR_ARRAY_IDX(chain, 0, const md_cert_t*)` performs an unchecked out-of-bounds/uninitialized read.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

`md_pubcert_load()` returns `APR_SUCCESS` with an empty certificate chain.

## Proof

`get_staging_certs_json()` receives `chain` from `md_pubcert_load()` and, on success, immediately reads index 0:

```c
rv = md_pubcert_load(md_reg_store_get(reg), MD_SG_STAGING, md->name, spec, &chain, p);
if (APR_SUCCESS == rv) {
    cert = APR_ARRAY_IDX(chain, 0, const md_cert_t*);
}
```

A practical trigger path exists:

- A staged renewal job exists, so `status_get_md_json()` loads `job.json`.
- `status_get_md_json()` calls `get_staging_certs_json()` while attaching staging certificate status.
- The staging area contains an empty `pubcert*.pem` chain file for one key spec.
- A status request reaches `md_status_get_md_json()` through the `md-status` handler or `/.httpd/certificate-status`.
- The empty chain is loaded successfully.
- `APR_ARRAY_IDX(chain, 0, const md_cert_t*)` reads from an APR array with `nelts == 0`.

The resulting value is pushed into `certs` and later processed by `status_get_certs_json()`.

## Why This Is A Real Bug

`APR_ARRAY_IDX` does not perform bounds checking. Reading element 0 from an APR array with `nelts == 0` accesses uninitialized array storage.

If the uninitialized value is non-NULL, it can be passed to `status_get_cert_json_ex()` and dereferenced through certificate helper functions, producing a realistic crash/DoS path. Even if the value happens to be NULL, the code still performs an out-of-bounds/uninitialized read.

## Fix Requirement

Only read certificate index 0 after verifying:

```c
chain && chain->nelts > 0
```

## Patch Rationale

The patch preserves existing behavior for valid non-empty chains and treats empty or missing chains as no certificate for that key spec. This matches the surrounding logic, where `cert` is initialized to NULL and NULL certificates are skipped later by `status_get_certs_json()`.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/md/md_status.c b/modules/md/md_status.c
index 3572168..6f040dc 100644
--- a/modules/md/md_status.c
+++ b/modules/md/md_status.c
@@ -209,7 +209,7 @@ static apr_status_t get_staging_certs_json(md_json_t **pjson, const md_t *md,
         spec = md_pkeys_spec_get(md->pks, i);
         cert = NULL;
         rv = md_pubcert_load(md_reg_store_get(reg), MD_SG_STAGING, md->name, spec, &chain, p);
-        if (APR_SUCCESS == rv) {
+        if (APR_SUCCESS == rv && chain && chain->nelts > 0) {
             cert = APR_ARRAY_IDX(chain, 0, const md_cert_t*);
         }
         APR_ARRAY_PUSH(certs, const md_cert_t*) = cert;
```