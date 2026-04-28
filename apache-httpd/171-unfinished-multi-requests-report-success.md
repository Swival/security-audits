# Unfinished Multi Requests Report Success

## Classification

Error-handling bug, medium severity.

## Affected Locations

`modules/md/md_curl.c:595`

## Summary

`md_curl_multi_perform()` can exit through an error path while requests are still active. During cleanup, it fires callbacks for every remaining request with `APR_SUCCESS` instead of the dispatcher error. This causes unfinished requests to report success even though the multi dispatcher failed.

## Provenance

Verified and reproduced from Swival Security Scanner findings: https://swival.dev

Confidence: certain.

## Preconditions

An active multi request remains queued when `md_curl_multi_perform()` exits with an error.

## Proof

Error paths from `nextreq`, `internals_setup`, or `curl_multi_*` failures set `rv` to an error and jump to `leave`.

At `leave`, the cleanup loop processes every remaining request:

```c
for (i = 0; i < requests->nelts; ++i) {
    req = APR_ARRAY_IDX(requests, i, md_http_request_t*);
    fire_status(req, APR_SUCCESS);
    ...
}
```

The dispatcher returns the error in `rv`, but callbacks for unfinished requests receive `APR_SUCCESS`.

This violates the API invariant documented in `md_http.h`: status callbacks receive `APR_SUCCESS` only when the operation succeeded. A request with only an `on_status` callback therefore observes success for work that did not complete. If an `on_response` callback exists and detects the incomplete response by returning an error, `on_status` may receive that callback error instead, but status-only requests remain affected.

## Why This Is A Real Bug

The request did not complete successfully, yet the cleanup path explicitly reports success to request callbacks. This creates inconsistent observable behavior: `md_curl_multi_perform()` returns an error while unfinished request callbacks are told the same operation succeeded.

The bug is reachable whenever queued requests remain and the multi dispatcher exits through an error path.

## Fix Requirement

Pass the dispatcher result `rv` to `fire_status()` for remaining requests during cleanup, rather than hardcoding `APR_SUCCESS`.

## Patch Rationale

`rv` already contains the reason `md_curl_multi_perform()` is leaving. Using it for unfinished requests preserves the callback contract and aligns per-request status with the function result.

Completed requests are unaffected because they are removed from `requests` before the cleanup loop.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/md/md_curl.c b/modules/md/md_curl.c
index fac2ab8..29cf500 100644
--- a/modules/md/md_curl.c
+++ b/modules/md/md_curl.c
@@ -594,7 +594,7 @@ leave:
                   "multi_perform[%d reqs]: leaving", requests->nelts);
     for (i = 0; i < requests->nelts; ++i) {
         req = APR_ARRAY_IDX(requests, i, md_http_request_t*);
-        fire_status(req, APR_SUCCESS);
+        fire_status(req, rv);
         sub_http = req->http;
         APR_ARRAY_PUSH(http_spares, md_http_t*) = sub_http;
         remove_from_curlm_and_destroy(req, curlm);
```