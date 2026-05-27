# Unbounded FastCGI Response Header Buffering

## Classification

Denial of service. Severity: Medium. Confidence: Certain.

## Affected Locations

- `lib/handler/fastcgi.c:634`
- Function: `handle_stdin_record`

## Summary

A malicious FastCGI upstream can send repeated `FCGI_STDOUT` records that never contain complete CGI response headers. Before response headers are accepted, H2O appends incomplete header bytes into `generator->resp.receiving` without enforcing a maximum size. This permits unbounded memory growth and can exhaust worker/process resources.

## Provenance

Verified by Swival security analysis and reproduction.

Scanner: [https://swival.dev](https://swival.dev)

## Preconditions

- H2O is configured to proxy requests to a FastCGI upstream.
- The FastCGI upstream is attacker-controlled or otherwise malicious.

## Proof

`on_read` dispatches complete `FCGI_STDOUT` records to `handle_stdin_record`.

Before `generator->sent_headers` is set, `handle_stdin_record` parses CGI response headers with `phr_parse_headers`.

If headers are incomplete, `phr_parse_headers` returns `-2`. In that path:

- The FastCGI record body is copied into `generator->resp.receiving`.
- `generator->resp.receiving->size` is increased.
- Later incomplete records append more bytes and reparse.
- No maximum buffered header size is checked before `h2o_buffer_reserve`.

An attacker-controlled upstream can keep sending unterminated header bytes within the I/O timeout window. `on_read` resets the timeout after reads, so continued traffic avoids timeout while growing memory.

`h2o_buffer_reserve` may grow buffers substantially, including mmap-backed storage after larger sizes, but the allocation remains unbounded and can cause denial of service through memory, address-space, or backing-store exhaustion.

## Why This Is A Real Bug

The vulnerable path occurs before response headers are completed, so normal response streaming limits do not apply. The existing code bounds neither the accumulated header buffer nor each append against a configured or global header limit. A malicious FastCGI peer can therefore force H2O to buffer arbitrary amounts of data for a single response that never becomes valid.

This is externally triggerable whenever H2O proxies to an attacker-controlled FastCGI backend.

## Fix Requirement

Enforce a maximum size for buffered FastCGI response headers before appending additional incomplete header bytes. If the accumulated size plus the incoming record content would exceed the limit, abort the FastCGI response handling and close/error the request.

## Patch Rationale

The patch checks `generator->resp.receiving->size + header->contentLength` against `H2O_MAX_REQLEN` before any buffering for header parsing. It also avoids integer underflow by testing:

- current buffered size exceeds the limit, or
- incoming content length exceeds remaining allowed capacity.

On violation, H2O logs `"received too large response headers"` and returns an error, causing the existing error handling path to close the generator and fail the request instead of allocating more memory.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/handler/fastcgi.c b/lib/handler/fastcgi.c
index dfe5b1825..f979bd241 100644
--- a/lib/handler/fastcgi.c
+++ b/lib/handler/fastcgi.c
@@ -591,6 +591,11 @@ static int handle_stdin_record(struct st_fcgi_generator_t *generator, struct st_
     }
 
     /* parse the headers using the input buffer (or keep it in response buffer and parse) */
+    if (generator->resp.receiving->size > H2O_MAX_REQLEN ||
+        header->contentLength > H2O_MAX_REQLEN - generator->resp.receiving->size) {
+        h2o_req_log_error(generator->req, MODULE_NAME, "received too large response headers");
+        return -1;
+    }
     num_headers = sizeof(headers) / sizeof(headers[0]);
     if (generator->resp.receiving->size == 0) {
         parse_result = phr_parse_headers(input->bytes + FCGI_RECORD_HEADER_SIZE, header->contentLength, headers, &num_headers, 0);
```