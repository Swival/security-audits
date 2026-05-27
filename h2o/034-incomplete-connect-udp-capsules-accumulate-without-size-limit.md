# Incomplete CONNECT-UDP Capsules Accumulate Without Size Limit

## Classification

Denial of service, medium severity. Confidence: certain.

## Affected Locations

- `lib/handler/connect.c:756`
- `lib/handler/connect.c:763-796`
- `lib/handler/connect.c:807-817`

## Summary

The CONNECT-UDP request-body path buffered incomplete Datagram Capsules in `self->udp.egress.buf` without enforcing `handler->config.max_buffer_size`.

An attacker could declare a very large capsule length, continuously send body bytes below that declared length, and force unbounded accumulation of attacker-controlled data in the proxy worker.

## Provenance

Verified and reproduced from a Swival.dev Security Scanner finding.

Scanner URL: https://swival.dev

## Preconditions

- CONNECT-UDP handler is enabled.
- ACL allows the chosen UDP destination.
- Attacker can open a CONNECT-UDP stream and send request-body data.

## Proof

The vulnerable path is:

1. `on_req_connect_udp` accepts a valid RFC 9298 CONNECT-UDP request.
2. `on_req_core` installs `udp_write_stream` as the request-body writer.
3. `udp_connect` installs `udp_write_stream` for subsequent body chunks.
4. `udp_do_write_stream` parses capsule bytes using `udp_get_next_chunk`.
5. If the capsule declares a length larger than available bytes, `udp_get_next_chunk` returns `datagram.base == NULL`.
6. Parsing stops with `off == 0`.
7. Since `chunk.len != off`, all unconsumed bytes are appended to `self->udp.egress.buf`.
8. No check compares the append size or resulting buffer size against `handler->config.max_buffer_size`.

Practical trigger:

1. Send a valid H1 RFC9298 CONNECT-UDP upgrade request to an allowed UDP destination.
2. After tunnel acceptance, send a Datagram Capsule header with type `0` and a very large QUIC-varint capsule length.
3. Continue sending body bytes while keeping total bytes below the declared capsule length.

Because the capsule never completes, no datagram is emitted, `off` remains zero, and every received byte remains buffered in `self->udp.egress.buf`. The IO timeout is reset on each chunk, so a client that keeps sending can grow this buffer until worker memory or backing storage is exhausted, or until `h2o_buffer_reserve` fatally aborts on allocation failure.

## Why This Is A Real Bug

`do_register` asserts `config->max_buffer_size != 0`, showing the handler has an intended buffering limit.

The TCP path buffers request data into a send buffer, but the CONNECT-UDP stream-capsule path had no equivalent size enforcement for incomplete capsule fragments. Incomplete capsules are explicitly retained for later parsing, making the buffer attacker-controlled and persistent across chunks.

This is not only a malformed-input rejection issue: the attacker can keep the stream active by sending more body bytes, which repeatedly resets IO timeout and grows `self->udp.egress.buf`.

## Fix Requirement

Before appending to `self->udp.egress.buf`, enforce `handler->config.max_buffer_size`.

The check must cover:

- Early data buffered before the UDP socket is open.
- Additional chunks appended to an existing incomplete capsule buffer.
- New incomplete capsule fragments buffered after parsing stops.
- Integer underflow/overflow in size calculations.

On overflow, abort the request-body write path by returning an error.

## Patch Rationale

The patch changes `udp_do_write_stream` from `void` to `int`, allowing buffer-limit violations to propagate as write failures.

It adds size checks before every append to `self->udp.egress.buf`:

- Existing-buffer append path checks both `chunk.len > max_buffer_size` and `current_size > max_buffer_size - chunk.len`.
- Fresh incomplete-fragment append path rejects `chunk.len - off > max_buffer_size`.
- Pre-socket buffering path applies the same cumulative bound check.

This enforces the configured maximum and prevents unbounded accumulation of incomplete CONNECT-UDP capsule data.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/handler/connect.c b/lib/handler/connect.c
index 22a56db46..ca1ebef7d 100644
--- a/lib/handler/connect.c
+++ b/lib/handler/connect.c
@@ -761,7 +761,7 @@ static void udp_write_stream_complete_delayed(h2o_timer_t *_timer)
     self->src_req->proceed_req(self->src_req, NULL);
 }
 
-static void udp_do_write_stream(struct st_connect_generator_t *self, h2o_iovec_t chunk)
+static int udp_do_write_stream(struct st_connect_generator_t *self, h2o_iovec_t chunk)
 {
     int from_buf = 0;
     size_t off = 0;
@@ -770,8 +770,12 @@ static void udp_do_write_stream(struct st_connect_generator_t *self, h2o_iovec_t
 
     if (self->udp.egress.buf->size != 0) {
         from_buf = 1;
-        if (chunk.len != 0)
+        if (chunk.len != 0) {
+            if (chunk.len > self->handler->config.max_buffer_size ||
+                self->udp.egress.buf->size > self->handler->config.max_buffer_size - chunk.len)
+                return -1;
             h2o_buffer_append(&self->udp.egress.buf, chunk.base, chunk.len);
+        }
         chunk.base = self->udp.egress.buf->bytes;
         chunk.len = self->udp.egress.buf->size;
     }
@@ -789,10 +793,13 @@ static void udp_do_write_stream(struct st_connect_generator_t *self, h2o_iovec_t
     if (from_buf) {
         h2o_buffer_consume(&self->udp.egress.buf, off);
     } else if (chunk.len != off) {
+        if (chunk.len - off > self->handler->config.max_buffer_size)
+            return -1;
         h2o_buffer_append(&self->udp.egress.buf, chunk.base + off, chunk.len - off);
     }
 
     h2o_timer_link(get_loop(self), 0, &self->udp.egress.delayed);
+    return 0;
 }
 
 static int udp_write_stream(void *_self, int is_end_stream)
@@ -813,12 +820,14 @@ static int udp_write_stream(void *_self, int is_end_stream)
 
     /* if the socket is not yet open, buffer input and return */
     if (self->sock == NULL) {
+        if (chunk.len > self->handler->config.max_buffer_size ||
+            self->udp.egress.buf->size > self->handler->config.max_buffer_size - chunk.len)
+            return -1;
         h2o_buffer_append(&self->udp.egress.buf, chunk.base, chunk.len);
         return 0;
     }
 
-    udp_do_write_stream(self, chunk);
-    return 0;
+    return udp_do_write_stream(self, chunk);
 }
 
 static void udp_write_datagrams(h2o_req_t *_req, h2o_iovec_t *datagrams, size_t num_datagrams)
```