# Header Validation Error Ignored

## Classification

Validation gap, low severity.

## Affected Locations

`modules/md/md_curl.c:339`

## Summary

`internals_setup` detects invalid request headers containing CR or LF through `curlify_headers`, but ignores the resulting `APR_EINVAL`. The request setup still succeeds, allowing the request to proceed without the caller-supplied custom header list.

This is not header injection: CR/LF values are prevented from reaching libcurl. The bug is that validation failure is not propagated and the request continues silently with intended headers omitted.

## Provenance

Reproduced and patched from a Swival Security Scanner finding: https://swival.dev

Confidence: certain.

## Preconditions

- A request contains caller-controlled headers.
- Any header key or value contains `\r` or `\n`.

## Proof

`internals_setup` iterates `req->headers` with `apr_table_do(curlify_headers, &ctx, req->headers, NULL)`.

`curlify_headers` rejects CR/LF in keys or values by setting:

```c
ctx->rv = APR_EINVAL;
return 0;
```

Before the patch, `internals_setup` assigned `internals->req_hdrs = ctx.hdrs` and only skipped `CURLOPT_HTTPHEADER` when `ctx.rv != APR_SUCCESS`. It did not assign `rv = ctx.rv` or abort setup.

As a result:

- `internals_setup` returned `APR_SUCCESS`.
- `md_curl_perform` proceeded to `curl_easy_perform`.
- `md_curl_multi_perform` proceeded to add the request to the curl multi handle.
- The request was sent without the intended custom headers.

## Why This Is A Real Bug

The code explicitly validates and rejects CR/LF in request headers, but the rejection is not enforced by the caller. This creates a mismatch between validation intent and runtime behavior.

A caller that supplied important headers, such as `Content-Type`, `Expect`, or authentication-like headers, receives no setup failure. Instead, the request can be sent with the header list omitted, which is a silent behavioral change and can cause incorrect or unsafe request semantics.

## Fix Requirement

If `curlify_headers` records a failure in `ctx.rv`, `internals_setup` must propagate that status and abort setup before the request can be performed or added to a multi handle.

## Patch Rationale

The patch checks `ctx.rv` immediately after header conversion. On failure, it assigns `rv = ctx.rv` and jumps to `leave`, causing `internals_setup` to return `APR_EINVAL` and clear `req->internals`.

Only after successful validation does the code assign `internals->req_hdrs` and configure `CURLOPT_HTTPHEADER`.

This preserves the existing CR/LF rejection behavior while making the validation failure effective.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/md/md_curl.c b/modules/md/md_curl.c
index fac2ab8..c786f4b 100644
--- a/modules/md/md_curl.c
+++ b/modules/md/md_curl.c
@@ -336,10 +336,12 @@ static apr_status_t internals_setup(md_http_request_t *req)
         ctx.hdrs = NULL;
         ctx.rv = APR_SUCCESS;
         apr_table_do(curlify_headers, &ctx, req->headers, NULL);
-        internals->req_hdrs = ctx.hdrs;
-        if (ctx.rv == APR_SUCCESS) {
-            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, internals->req_hdrs);
+        if (ctx.rv != APR_SUCCESS) {
+            rv = ctx.rv;
+            goto leave;
         }
+        internals->req_hdrs = ctx.hdrs;
+        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, internals->req_hdrs);
     }
     
     md_log_perror(MD_LOG_MARK, MD_LOG_TRACE3, 0, req->pool,
```