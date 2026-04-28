# OCSP response times accepted without validity check

## Classification

Validation gap, medium severity. Confidence: certain.

## Affected Locations

`modules/md/md_ocsp.c:707`

## Summary

`ostat_on_resp` accepted a successful OCSP response for the requested certificate ID after parsing `thisUpdate` and `nextUpdate`, but did not verify that the current time was inside that validity window. As a result, stale responses with an expired `nextUpdate`, or not-yet-valid responses with a future `thisUpdate`, could be stored and later stapled.

## Provenance

Reported and validated by Swival Security Scanner: https://swival.dev

## Preconditions

- The OCSP responder returns a successful OCSP response.
- The response contains a matching status entry for the requested `certid`.
- The status is `GOOD` or `REVOKED`.
- The response `thisUpdate`/`nextUpdate` validity period does not include the current time.

## Proof

- `ostat_on_resp` receives the network OCSP response and parses it into `basic_resp`.
- `OCSP_resp_find_status` supplies `bstatus`, `bup`, and `bnextup` for the matching certificate ID.
- The code accepts `GOOD` or `REVOKED` statuses and derives `valid.start` from `thisUpdate` and `valid.end` from `nextUpdate`.
- Before the patch, no `OCSP_check_validity` call or equivalent `now >= thisUpdate && now <= nextUpdate` check existed.
- The response was installed in memory through `ostat_set` and persisted through `ocsp_status_save`.
- `md_ocsp_get_status` later returned `ostat->resp_der` without checking that the current time was inside `resp_valid`.
- mod_ssl staples the hook-provided OCSP bytes with `SSL_set_tlsext_status_ocsp_resp`.

## Why This Is A Real Bug

OCSP `thisUpdate` and `nextUpdate` bound the time interval for which the responder’s status assertion is valid. Accepting a response outside that interval allows invalid freshness data to be cached and served. Renewal scheduling does not prevent this because the invalid response is already stored and can be returned for stapling before or during renewal attempts.

## Fix Requirement

Reject any OCSP response when the current time is before `thisUpdate` or after `nextUpdate`, including the defaulted validity interval used when `nextUpdate` is absent.

## Patch Rationale

The patch captures `now` once, derives the OCSP validity interval, then rejects the response before calling `ostat_set` or `ocsp_status_save` if `now < valid.start || now > valid.end`.

This prevents both stale and not-yet-valid OCSP responses from entering memory or persistent storage. Reusing the same `now` for the default `thisUpdate` fallback and for `ostat_set` also avoids inconsistent timing decisions within the same response-processing path.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/md/md_ocsp.c b/modules/md/md_ocsp.c
index d2dfd73..763aa66 100644
--- a/modules/md/md_ocsp.c
+++ b/modules/md/md_ocsp.c
@@ -595,6 +595,7 @@ static apr_status_t ostat_on_resp(const md_http_response_t *resp, void *baton)
     md_data_t der, new_der;
     md_timeperiod_t valid;
     md_ocsp_cert_stat_t nstat;
+    apr_time_t now;
     
     der.data = new_der.data = NULL;
     der.len  = new_der.len = 0;
@@ -692,7 +693,8 @@ static apr_status_t ostat_on_resp(const md_http_response_t *resp, void *baton)
     new_der.len = (apr_size_t)n;
     new_der.free_data = md_openssl_free;
     nstat = (bstatus == V_OCSP_CERTSTATUS_GOOD)? MD_OCSP_CERT_ST_GOOD : MD_OCSP_CERT_ST_REVOKED;
-    valid.start = bup? md_asn1_generalized_time_get(bup) : apr_time_now();
+    now = apr_time_now();
+    valid.start = bup? md_asn1_generalized_time_get(bup) : now;
     if (bnextup) {
         valid.end = md_asn1_generalized_time_get(bnextup);
     }
@@ -701,10 +703,17 @@ static apr_status_t ostat_on_resp(const md_http_response_t *resp, void *baton)
          * Refresh attempts will be started some time earlier. */
         valid.end = valid.start + apr_time_from_sec(MD_SECS_PER_DAY / 2);
     }
+    if (now < valid.start || now > valid.end) {
+        rv = APR_EINVAL;
+        md_result_printf(update->result, rv, "OCSP response outside validity period %s",
+                         md_timeperiod_print(req->pool, &valid));
+        md_result_log(update->result, MD_LOG_DEBUG);
+        goto cleanup;
+    }
     
     /* First, update the instance with a copy */
     apr_thread_mutex_lock(ostat->reg->mutex);
-    ostat_set(ostat, nstat, &new_der, &valid, apr_time_now());
+    ostat_set(ostat, nstat, &new_der, &valid, now);
     apr_thread_mutex_unlock(ostat->reg->mutex);
     
     /* Next, save the original response */
```