# nghttp2 consume errors ignored

## Classification

error-handling bug; severity medium; confidence certain.

## Affected Locations

`modules/http2/h2_stream.c:1335`

## Summary

`h2_stream_in_consumed()` reported request-body bytes to libnghttp2 with `nghttp2_session_consume()` but ignored the return value. If libnghttp2 failed while accounting consumed bytes, Apache still decremented its local `consumed` counter and returned `APR_SUCCESS`, making callers believe HTTP/2 flow-control accounting succeeded when it did not.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

## Preconditions

`nghttp2_session_consume()` returns an error while processing consumed input bytes for a stream.

## Proof

The reproduced path is:

- `h2_mplx.c:107` calls `h2_stream_in_consumed(ctx, length)` from the beam consumption callback and ignores the returned `apr_status_t`.
- `h2_bucket_beam.c:113` reports consumed byte deltas, invokes the callback, then advances `beam->recv_bytes_reported += len` at `h2_bucket_beam.c:128` regardless of whether HTTP/2 flow-control accounting succeeded.
- `modules/http2/h2_stream.c:1325` enters `h2_stream_in_consumed()` with the consumed byte amount.
- `modules/http2/h2_stream.c:1335` calls `nghttp2_session_consume(session->ngh2, stream->id, len)` but discards the returned `int`.
- `modules/http2/h2_stream.c:1336` decrements `consumed` regardless of the libnghttp2 result.
- `modules/http2/h2_stream.c:1383` returns `APR_SUCCESS` unconditionally.

The reproducer confirmed that a libnghttp2 failure, for example an allocation failure while queuing a `WINDOW_UPDATE`, is not observable by callers and the beam bytes are still marked as reported.

## Why This Is A Real Bug

`nghttp2_session_consume()` is the API that informs libnghttp2 that inbound DATA bytes have been consumed and that corresponding flow-control state may be updated. Its return value communicates whether that accounting succeeded.

Ignoring that result creates a false acknowledgment:

- Apache records the consumed bytes as reported.
- Callers receive `APR_SUCCESS`.
- libnghttp2 may not have updated HTTP/2 flow-control state.
- The session can continue with request-body consumption no longer reliably reflected in HTTP/2 windows.

This can cause upload stalls or continued operation after a fatal nghttp2 error.

## Fix Requirement

Check the return value from each `nghttp2_session_consume()` call and stop processing immediately if it fails. Return an APR error before decrementing the remaining consumed byte count.

## Patch Rationale

The patch stores the libnghttp2 return value in `rv`, checks it before mutating local consumption state, and returns `APR_EGENERAL` on failure. This prevents Apache from falsely marking bytes as successfully accounted when libnghttp2 rejected the consume operation.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/http2/h2_stream.c b/modules/http2/h2_stream.c
index f0e671c..08e77d7 100644
--- a/modules/http2/h2_stream.c
+++ b/modules/http2/h2_stream.c
@@ -1332,7 +1332,10 @@ apr_status_t h2_stream_in_consumed(h2_stream *stream, apr_off_t amount)
         
         while (consumed > 0) {
             int len = (consumed > INT_MAX)? INT_MAX : (int)consumed;
-            nghttp2_session_consume(session->ngh2, stream->id, len);
+            int rv = nghttp2_session_consume(session->ngh2, stream->id, len);
+            if (rv != 0) {
+                return APR_EGENERAL;
+            }
             consumed -= len;
         }
```