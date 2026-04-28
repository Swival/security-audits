# Ignored Path Normalization Failure

## Classification

High severity validation gap.

## Affected Locations

`server/request.c:273`

## Summary

`ap_process_request_internal()` correctly checks the first `ap_normalize_path()` call, but ignores the result of the second normalization performed after encoded slash decoding. When `AllowEncodedSlashes` and `DecodeEncodedSlashes` are enabled, URL unescaping can create new `/../` segments that violate `AP_NORMALIZE_NOT_ABOVE_ROOT`. The second normalization detects this failure, but the ignored return value allows request processing to continue.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- `AllowEncodedSlashes` enabled.
- `DecodeEncodedSlashes` enabled.
- Request URI path contains encoded slash dot-segments.
- Example trigger: `/%2e%2e%2fserver-status`

## Proof

The request URI path enters `ap_process_request_internal()` as `r->parsed_uri.path`.

A concrete path such as:

```text
/%2e%2e%2fserver-status
```

follows this flow:

1. The first `ap_normalize_path()` decodes unreserved dots but does not decode `%2f`, so it does not reject the path.
2. `ap_unescape_url_ex()` decodes `%2f` because encoded slash decoding is enabled.
3. The path becomes `/../server-status`.
4. The second `ap_normalize_path()` sees an above-root `..`, returns failure, and rewrites the path to `/server-status`.
5. The return value is ignored, so processing continues through location walking, translation, storage mapping, and auth phases instead of returning `HTTP_BAD_REQUEST`.

## Why This Is A Real Bug

`AP_NORMALIZE_NOT_ABOVE_ROOT` is an explicit validation invariant: above-root path traversal segments must be rejected. The first normalization enforces this invariant before URL unescaping. After encoded slash decoding, the same invariant can be violated again because `%2f` can become `/` and create new path segments.

The second normalization already detects this condition by returning failure. Ignoring that failure converts a rejected URI into an accepted normalized target URI, allowing ordinary remote requests to proceed despite core normalization marking the path invalid.

## Fix Requirement

Check the second `ap_normalize_path()` return value and return `HTTP_BAD_REQUEST` on failure.

## Patch Rationale

The patch makes the post-unescape normalization behave like the initial normalization. If decoding encoded slashes creates an invalid path, the request is logged as an invalid URI path and rejected immediately with `HTTP_BAD_REQUEST`.

This preserves the intended normalized-path invariant after all configured decoding has occurred.

## Residual Risk

None

## Patch

```diff
diff --git a/server/request.c b/server/request.c
index 5599b2c..d2bc4c7 100644
--- a/server/request.c
+++ b/server/request.c
@@ -265,7 +265,11 @@ AP_DECLARE(int) ap_process_request_internal(request_rec *r)
             /* Decoding slashes might have created new // or /./ or /../
              * segments (e.g. "/.%2F/"), so re-normalize.
              */
-            ap_normalize_path(r->parsed_uri.path, normalize_flags);
+            if (!ap_normalize_path(r->parsed_uri.path, normalize_flags)) {
+                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(10244)
+                              "invalid URI path (%s)", r->unparsed_uri);
+                return HTTP_BAD_REQUEST;
+            }
         }
     }
```