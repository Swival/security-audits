# Output Buffer Length Not Adjusted After Skip

## Classification

Memory safety, high severity, confirmed.

## Affected Locations

`modules/filters/mod_xml2enc.c:165`

## Summary

`fix_skipto()` advances `ctx->buf` past a skippable response prefix but does not reduce `ctx->bblen`, which still represents the original allocation size. Later, `xml2enc_ffunc()` uses the advanced pointer as the APR output buffer while advertising the unchanged `ctx->bblen` capacity. This can allow `apr_xlate_conv_buffer()` to write past the remaining allocation.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- `xml2StartParse` is configured.
- The response contains a skippable prefix before a recognized start element.
- The filter initializes conversion state and reaches `fix_skipto()`.
- A later conversion can write enough bytes to fill the advertised output capacity.

## Proof

Reachability is confirmed because `xml2enc_filter_init()` sets `ENC_SKIPTO` when `xml2StartParse` exists in configuration at `modules/filters/mod_xml2enc.c:312`.

`xml2enc_ffunc()` allocates `ctx->buf` for `ctx->bblen + 1` bytes at `modules/filters/mod_xml2enc.c:384`, sets `ctx->bytes` from `ctx->bblen`, flattens the brigade into that buffer, and NUL-terminates it.

`fix_skipto()` finds a later recognized start tag, deletes skipped buckets, subtracts the skipped byte count from `ctx->bytes`, and advances `ctx->buf = p` at `modules/filters/mod_xml2enc.c:166` and `modules/filters/mod_xml2enc.c:167`.

Later, conversion resets `ctx->bytes` to the unchanged `ctx->bblen` and passes the advanced `ctx->buf` to `apr_xlate_conv_buffer()` at `modules/filters/mod_xml2enc.c:510` and `modules/filters/mod_xml2enc.c:511`.

After a skip of `s` bytes, only `ctx->bblen + 1 - s` bytes remain in the allocation, but APR is told it may write `ctx->bblen` bytes. Expanding conversions, such as ISO-8859-1 high-bit bytes to UTF-8, can fill the advertised capacity and write past the pool allocation.

## Why This Is A Real Bug

`ctx->bblen` is used as the output buffer capacity for `ctx->buf`. Once `ctx->buf` is advanced into the allocation, the original capacity is no longer valid for that pointer. The code preserves the old capacity while changing the base pointer, so subsequent writes can exceed the memory remaining after the new pointer.

The bug is not merely a length accounting mismatch for input data. The same stale length is later passed to `apr_xlate_conv_buffer()` as writable output capacity, creating an actual out-of-bounds write condition.

## Fix Requirement

The buffer pointer and capacity must remain consistent after skipping bytes. Either:

- keep `ctx->buf` at the allocation base and adjust only the logical data view, or
- reduce `ctx->bblen` by the skipped offset before using the advanced `ctx->buf`.

## Patch Rationale

The patch reduces `ctx->bblen` by the same skipped offset already subtracted from `ctx->bytes` before advancing `ctx->buf`.

This preserves the existing behavior of using the recognized start element as the new buffer start while ensuring later conversion code advertises only the writable capacity that remains from the advanced pointer.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/filters/mod_xml2enc.c b/modules/filters/mod_xml2enc.c
index eb05c18..20862bb 100644
--- a/modules/filters/mod_xml2enc.c
+++ b/modules/filters/mod_xml2enc.c
@@ -164,6 +164,7 @@ static void fix_skipto(request_rec* r, xml2ctx* ctx)
                         apr_bucket_delete(b);
                     }
                     ctx->bytes -= (p-ctx->buf);
+                    ctx->bblen -= (p-ctx->buf);
                     ctx->buf = p ;
                     found = 1;
                     ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01428)
```