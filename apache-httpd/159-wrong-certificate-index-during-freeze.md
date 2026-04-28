# Wrong Certificate Index During Freeze

## Classification

Logic error, medium severity, confirmed with reproduction.

## Affected Locations

`modules/md/md_reg.c:1109`

## Summary

`md_reg_freeze_domains()` preloads public certificates before setting `reg->domains_frozen`. It iterates managed domains with `i` and certificate indexes with `j`, but calls `md_reg_get_pubcert()` with `i` instead of `j`.

As a result, the freeze step can cache the wrong certificate index and fail to cache a present later-index certificate. Once domains are frozen, `md_reg_get_pubcert()` no longer loads missing entries from disk, so later callers can observe `APR_ENOENT` even when the certificate exists.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

Multiple managed domains or an MD with multiple certificates is frozen.

A practical trigger is:

- An MD has multiple key specs/certificates, such as EC then RSA.
- An earlier certificate index is missing.
- A later certificate index exists in the domains store.
- `state_init()` caches the earlier missing certificate and exits.
- `md_reg_freeze_domains()` then requests the wrong index in its inner loop.

## Proof

The affected code in `md_reg_freeze_domains()` uses nested loops:

```c
for (i = 0; i < mds->nelts; ++i) {
    md = APR_ARRAY_IDX(mds, i, md_t*);
    for (j = 0; j < md_cert_count(md); ++j) {
        rv = md_reg_get_pubcert(&pubcert, reg, md, i, reg->p);
        if (APR_SUCCESS != rv && !APR_STATUS_IS_ENOENT(rv)) goto leave;
    }
}
```

The inner loop variable `j` is the certificate index. The call incorrectly passes `i`, which is the managed-domain index.

The reproduced behavior confirms that certificate indexes may not be cached before freeze:

- `state_init()` can cache an earlier missing certificate and stop.
- `md_reg_freeze_domains()` repeatedly requests the wrong index.
- A later present certificate remains uncached.
- After `domains_frozen` is set, `md_reg_get_pubcert(md, later_index)` returns `APR_ENOENT` even though the certificate exists on disk.

Callers depending on `md_reg_get_pubcert()` after freeze include status generation and renewal/validity helpers at `modules/md/md_status.c:237`, `modules/md/md_reg.c:697`, `modules/md/md_reg.c:744`, and `modules/md/md_reg.c:1431`.

## Why This Is A Real Bug

`md_reg_get_pubcert()` only loads from the backing store when domains are not frozen:

```c
if (!pubcert && !reg->domains_frozen) {
    rv = md_util_pool_vdo(pubcert_load, reg, reg->p, &pubcert, MD_SG_DOMAINS, md, i, NULL);
    ...
}
```

Therefore, `md_reg_freeze_domains()` must prefill `reg->certs` for every certificate index that later code may request. Passing the domain-loop index breaks that invariant.

The bug is observable because later certificate indexes can exist on disk but remain absent from `reg->certs`. Once frozen, the registry treats those uncached entries as unavailable.

## Fix Requirement

Pass the certificate-loop index `j` to `md_reg_get_pubcert()` inside `md_reg_freeze_domains()`.

## Patch Rationale

The patch changes only the incorrect argument:

```diff
-            rv = md_reg_get_pubcert(&pubcert, reg, md, i, reg->p);
+            rv = md_reg_get_pubcert(&pubcert, reg, md, j, reg->p);
```

This aligns the preload call with the inner loop and with the semantics of `md_reg_get_pubcert()`, whose fourth parameter is the certificate index.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/md/md_reg.c b/modules/md/md_reg.c
index 36d1944..1ddb469 100644
--- a/modules/md/md_reg.c
+++ b/modules/md/md_reg.c
@@ -1382,7 +1382,7 @@ apr_status_t md_reg_freeze_domains(md_reg_t *reg, apr_array_header_t *mds)
     for (i = 0; i < mds->nelts; ++i) {
         md = APR_ARRAY_IDX(mds, i, md_t*);
         for (j = 0; j < md_cert_count(md); ++j) {
-            rv = md_reg_get_pubcert(&pubcert, reg, md, i, reg->p);
+            rv = md_reg_get_pubcert(&pubcert, reg, md, j, reg->p);
             if (APR_SUCCESS != rv && !APR_STATUS_IS_ENOENT(rv)) goto leave;
         }
     }
```