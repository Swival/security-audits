# null convset retained in conversion loop

## Classification

Invariant violation; medium severity.

## Affected Locations

`modules/filters/mod_xml2enc.c:537`

## Summary

`xml2enc_ffunc()` can clear `ctx->convset` after an unhandled conversion error but continue the same conversion loop with input bytes remaining. The next loop iteration calls `apr_xlate_conv_buffer()` with `ctx->convset == NULL`, violating the APR xlate API invariant and plausibly crashing the worker handling the request.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- `mod_xml2enc` output filtering is active for a text or XML response.
- The filter has initialized an APR xlate conversion handle.
- A data bucket contains convertible input followed by bytes that cause `apr_xlate_conv_buffer()` to return an unhandled non-success status while `insz > 0`.

## Proof

Response body bytes enter `xml2enc_ffunc()` through output brigade data buckets.

Inside the conversion loop, the code calls:

```c
rv = apr_xlate_conv_buffer(ctx->convset, buf+(bytes - insz),
                           &insz, ctx->buf, &ctx->bytes);
```

For `APR_SUCCESS`, `APR_EINCOMPLETE`, and `APR_EINVAL`, the loop has explicit handling. For any other return value, the `default` arm logs the conversion failure, sets:

```c
ctx->convset = NULL;
```

then flushes and cleans `ctx->bbnext`.

The original code does not break, return, or force loop termination after nulling `ctx->convset`. If `insz > 0`, the `while (insz > 0)` loop continues. On the next iteration, if `ctx->bytes == ctx->bblen` is false, execution reaches `apr_xlate_conv_buffer()` again with a null conversion handle.

The reproduced trigger is an initialized xml2enc conversion filter using an APR multibyte converter, receiving a text/XML bucket with at least one complete convertible character followed by an incomplete multibyte sequence at the bucket end. That produces remaining input after partial conversion and reaches the null-convset state before another loop iteration.

## Why This Is A Real Bug

`ctx->convset` is the conversion handle passed directly to `apr_xlate_conv_buffer()`. Passing `NULL` after the filter has already decided conversion is unavailable is not a valid fallback path; it violates the conversion API invariant.

The surrounding code already recognizes `!ctx->convset` as a special state before entering conversion: it passes the saved brigade through raw, removes the filter, and returns. The bug is that the same state can be created inside the active conversion loop without immediately leaving that loop.

Impact is request/worker instability for reachable filtered responses whose converter reports an unhandled conversion error while bytes remain.

## Fix Requirement

After setting `ctx->convset = NULL`, the conversion loop must not call `apr_xlate_conv_buffer()` again. Remaining unconverted input must be preserved and passed raw, matching the existing no-convset fallback behavior.

## Patch Rationale

The patch terminates conversion after the fallback decision and preserves remaining bytes:

- If flushing succeeds and `insz > 0`, the remaining unconverted bytes are copied into a heap bucket and reinserted at the head of `bb`.
- `insz = 0` exits the inner conversion loop, preventing another `apr_xlate_conv_buffer()` call with a null handle.
- After any temporary read bucket is destroyed, the new `!ctx->convset && rv == APR_SUCCESS` branch passes the remaining brigade downstream, removes the xml2enc filter, and returns.
- Using `apr_bucket_heap_create()` is necessary because the original data buffer may belong to a bucket that is destroyed immediately after the conversion block.

This preserves the intended “try it raw” fallback while avoiding reuse of a null conversion handle.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/filters/mod_xml2enc.c b/modules/filters/mod_xml2enc.c
index eb05c18..df7ea91 100644
--- a/modules/filters/mod_xml2enc.c
+++ b/modules/filters/mod_xml2enc.c
@@ -549,6 +549,12 @@ static apr_status_t xml2enc_ffunc(ap_filter_t* f, apr_bucket_brigade* bb)
                             ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, f->r, APLOGNO(01446)
                                           "ap_fflush failed");
                         apr_brigade_cleanup(ctx->bbnext);
+                        if (rv == APR_SUCCESS && insz > 0) {
+                            b = apr_bucket_heap_create(buf+(bytes - insz), insz,
+                                                       NULL, bb->bucket_alloc);
+                            APR_BRIGADE_INSERT_HEAD(bb, b);
+                        }
+                        insz = 0;
                     }
                 }
             } else {
@@ -557,6 +563,11 @@ static apr_status_t xml2enc_ffunc(ap_filter_t* f, apr_bucket_brigade* bb)
             }
             if (bdestroy)
                 apr_bucket_destroy(bdestroy);
+            if (!ctx->convset && rv == APR_SUCCESS) {
+                rv = ap_pass_brigade(f->next, bb);
+                ap_remove_output_filter(f);
+                return rv;
+            }
             if (rv != APR_SUCCESS)
                 return rv;
         }
```