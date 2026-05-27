# CONTINUATION Stream ID Can Switch Response Streams

## Classification

- Type: Injection
- Severity: Medium
- Confidence: Certain

## Affected Locations

- `lib/common/http2client.c:475`
- Affected functions:
  - `handle_headers_frame`
  - `expect_continuation_of_headers`

## Summary

The HTTP/2 client accepts a `CONTINUATION` frame on a different stream than the preceding fragmented `HEADERS` frame.

When a `HEADERS` frame lacks `END_HEADERS`, the client stores the partial header block in `conn->input.headers_unparsed` and switches the frame reader to `expect_continuation_of_headers`. The code did not remember the originating stream ID. The continuation handler only verified that the next frame type was `CONTINUATION`, then looked up `frame.stream_id` and dispatched the completed decoded header block to that stream.

A malicious HTTP/2 server can therefore start a response header block on stream A and finish it with a `CONTINUATION` frame on stream B, causing response headers to be delivered to the wrong request stream.

## Provenance

- Verified by Swival security analysis.
- Scanner: [Swival.dev Security Scanner](https://swival.dev)
- Reproduced: yes
- Patch provided: yes

## Preconditions

- The client has multiple active HTTP/2 streams on the same server connection.
- The peer is a malicious or compromised HTTP/2 server/backend capable of controlling response frames.

## Proof

Reproduced attack sequence:

1. Client opens streams `1` and `3` on the same HTTP/2 connection.
2. Malicious server sends a valid response header block split into two fragments.
3. First fragment is sent as `HEADERS` on stream `1` without `END_HEADERS`.
4. Second fragment is sent as `CONTINUATION` on stream `3` with `END_HEADERS`.

Observed vulnerable behavior:

- `handle_headers_frame` stores the fragmented header block in `conn->input.headers_unparsed`.
- It sets `conn->input.read_frame` to `expect_continuation_of_headers`.
- It does not store the stream ID of the original `HEADERS` frame.
- `expect_continuation_of_headers` checks only that the next frame type is `CONTINUATION`.
- It then uses `get_stream(conn, frame.stream_id)` with the `CONTINUATION` frame’s stream ID.
- The combined HPACK block is decoded and dispatched through `on_head` or `on_trailers` for stream `3`.

For a normal response header case, `on_head` invokes:

```c
stream->super._cb.on_head(&stream->super, ...)
```

Therefore the caller associated with request stream `3` observes headers that began on stream `1`.

## Why This Is A Real Bug

HTTP/2 requires `CONTINUATION` frames to continue the header block on the same stream as the preceding `HEADERS` frame. Accepting a different stream ID violates HTTP/2 framing semantics and creates cross-stream response association confusion.

The impact is practical:

- Response headers can be injected into a different active request stream.
- Application callbacks receive headers for the wrong request.
- The original stream does not receive the completed header block.
- This is reachable from a malicious HTTP/2 server with only multiple concurrent client streams.

## Fix Requirement

The client must remember the stream ID of a fragmented `HEADERS` block and reject any subsequent `CONTINUATION` frame whose stream ID differs.

Required behavior:

- On fragmented `HEADERS`, store `frame->stream_id`.
- In `expect_continuation_of_headers`, require `frame.stream_id == stored_stream_id`.
- Return `H2O_HTTP2_ERROR_PROTOCOL` on mismatch.

## Patch Rationale

The patch adds `headers_unparsed_stream_id` to the input state and sets it when a fragmented `HEADERS` frame is stored.

Before appending a `CONTINUATION` payload or dispatching decoded headers, the continuation handler now validates that the `CONTINUATION` frame’s stream ID matches the original `HEADERS` stream ID.

This preserves the existing buffering and decoding behavior while enforcing the missing HTTP/2 stream association invariant.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/common/http2client.c b/lib/common/http2client.c
index 36608ebef..307aeef79 100644
--- a/lib/common/http2client.c
+++ b/lib/common/http2client.c
@@ -73,6 +73,7 @@ struct st_h2o_http2client_conn_t {
         h2o_http2_window_t window;
         ssize_t (*read_frame)(struct st_h2o_http2client_conn_t *conn, const uint8_t *src, size_t len, const char **err_desc);
         h2o_buffer_t *headers_unparsed;
+        uint32_t headers_unparsed_stream_id;
     } input;
     h2o_mem_pool_t rst_streams_pool;
 };
@@ -459,6 +460,10 @@ static ssize_t expect_continuation_of_headers(struct st_h2o_http2client_conn_t *
         *err_desc = "expected CONTINUATION frame";
         return H2O_HTTP2_ERROR_PROTOCOL;
     }
+    if (frame.stream_id != conn->input.headers_unparsed_stream_id) {
+        *err_desc = "unexpected stream id in CONTINUATION frame";
+        return H2O_HTTP2_ERROR_PROTOCOL;
+    }
 
     stream = get_stream(conn, frame.stream_id);
     if (stream != NULL && stream->state.res == STREAM_STATE_CLOSED) {
@@ -644,6 +649,7 @@ static int handle_headers_frame(struct st_h2o_http2client_conn_t *conn, h2o_http
     if ((frame->flags & H2O_HTTP2_FRAME_FLAG_END_HEADERS) == 0) {
         /* header is not complete, store in buffer */
         conn->input.read_frame = is_end_stream ? expect_continuation_of_headers_eos : expect_continuation_of_headers_no_eos;
+        conn->input.headers_unparsed_stream_id = frame->stream_id;
         h2o_buffer_init(&conn->input.headers_unparsed, &h2o_socket_buffer_prototype);
         h2o_buffer_reserve(&conn->input.headers_unparsed, payload.headers_len);
         memcpy(conn->input.headers_unparsed->bytes, payload.headers, payload.headers_len);
```