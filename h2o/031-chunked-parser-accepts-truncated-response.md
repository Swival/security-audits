# Chunked Parser Accepts Truncated Response

## Classification

- Type: `security_control_failure`
- Severity: Medium
- Confidence: Certain

## Affected Locations

- `lib/common/http1client.c:313`
- Function: `on_body_chunked`

## Summary

The HTTP/1 client chunked-body parser accepted a prematurely closed chunked response as a complete response if at least one full nonterminal chunk had already been decoded. An attacker-controlled HTTP/1 origin could send a valid chunk, omit the required terminating zero-size chunk, close the connection, and cause the client to report normal end-of-stream instead of an I/O error.

## Provenance

- Verified by Swival security analysis.
- Scanner: [Swival.dev Security Scanner](https://swival.dev)

## Preconditions

- The client accepts a chunked HTTP/1 response from an attacker-controlled origin.

## Proof

`on_body_chunked` handles socket read errors while parsing `Transfer-Encoding: chunked` responses.

Before the patch, when `err == h2o_socket_error_closed`, the code special-cased connection close as successful completion if:

- the chunked decoder was not currently inside chunk data, and
- `_seen_at_least_one_chunk` was true.

That flag becomes true after any decoded chunk leaves body bytes in the input buffer. Therefore, a malicious origin could send:

```http
HTTP/1.1 200 OK
Transfer-Encoding: chunked

5
hello
```

and then close the TCP connection without sending the required terminating chunk:

```http
0

```

The vulnerable path then:

- set `_do_keepalive = 0`,
- set `state.res = STREAM_STATE_CLOSED`,
- recorded `response_end_at`,
- called `call_on_body(client, h2o_httpclient_error_is_eos)`,
- closed the response normally.

This caused an incomplete chunked response to be reported as successful end-of-stream.

The reproduced behavior confirmed that existing consumers treat `h2o_httpclient_error_is_eos` as successful completion, including proxy response handling that marks the response complete rather than reporting an upstream error.

## Why This Is A Real Bug

HTTP/1 chunked transfer coding is complete only after the terminating zero-size chunk and optional trailers are parsed. A peer close before that terminator is a premature EOF, not a valid end of message.

The vulnerable code implemented a fail-open completeness check: it accepted a syntactically incomplete chunked response solely because the close occurred between chunks after at least one chunk had been seen. This lets a hostile origin truncate response bodies while the client reports success to application code.

## Fix Requirement

Require the terminating zero-size chunk for chunked responses. Any socket close before the chunked decoder reports completion must be treated as an I/O error.

## Patch Rationale

The patch removes the special-case that converted `h2o_socket_error_closed` into `h2o_httpclient_error_is_eos` for partially decoded chunked responses.

After the patch, all read errors during chunked-body parsing, including peer close before the terminating zero chunk, are handled by:

```c
on_error(client, h2o_httpclient_error_io);
```

Valid completion remains handled only by `phr_decode_chunked` returning completion during normal parsing.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/common/http1client.c b/lib/common/http1client.c
index 3d404a4a2..bd4337376 100644
--- a/lib/common/http1client.c
+++ b/lib/common/http1client.c
@@ -315,21 +315,7 @@ static void on_body_chunked(h2o_socket_t *sock, const char *err)
     h2o_timer_unlink(&client->super._timeout);
 
     if (err != NULL) {
-        if (err == h2o_socket_error_closed && !phr_decode_chunked_is_in_data(&client->_body_decoder.chunked.decoder) &&
-            client->_seen_at_least_one_chunk) {
-            /*
-             * if the peer closed after a full chunk, treat this
-             * as if the transfer had complete, browsers appear to ignore
-             * a missing 0\r\n chunk
-             */
-            client->_do_keepalive = 0;
-            client->state.res = STREAM_STATE_CLOSED;
-            client->super.timings.response_end_at = h2o_gettimeofday(client->super.ctx->loop);
-            call_on_body(client, h2o_httpclient_error_is_eos);
-            close_response(client);
-        } else {
-            on_error(client, h2o_httpclient_error_io);
-        }
+        on_error(client, h2o_httpclient_error_io);
         return;
     }
     uint64_t size = sock->bytes_read - client->_socket_bytes_processed;
```