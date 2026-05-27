# Piped Response Error Path Uses Disposed Generator

## Classification

- Type: Memory corruption
- Impact: Use-after-free in proxy worker
- Severity: High
- Confidence: Certain

## Affected Locations

- `lib/core/proxy.c:512`
- Function: `on_body_piped`

## Summary

The zero-copy piped response body callback can continue using `rp_generator_t *self` after `on_body_on_close` synchronously disposes the generator.

In the non-piped body path, `on_body` protects this exact call with a `generator_disposed` guard. The piped path, `on_body_piped`, lacked the same guard and then accessed `self->sending`, `self->pipe_sender`, and could call `do_send_from_pipe(self)` after disposal.

## Provenance

- Verified by Swival security analysis.
- Scanner: [Swival.dev Security Scanner](https://swival.dev)
- Reproduced: Yes
- Finding: `piped response error path uses disposed generator`

## Preconditions

- Zero-copy pipe is enabled.
- Downstream request body uses `proceed_req`.
- Upstream response body is delivered through the piped path.
- Upstream closes or errors the piped response while the downstream request body is still streaming.

## Proof

`on_head` enables the piped body callback when a pipe reader exists and `h2o_pipe_sender_start` succeeds:

```c
args->pipe_reader->on_body_piped = on_body_piped;
```

`on_body_piped` calls `on_body_on_close(self, errstr)` on any body error:

```c
if (errstr != NULL)
    on_body_on_close(self, errstr);
if (!self->sending.inflight && !self->pipe_sender.inflight)
    do_send_from_pipe(self);
```

`on_body_on_close` can synchronously invoke downstream request continuation on error:

```c
if (self->src_req->proceed_req != NULL)
    self->src_req->proceed_req(self->src_req, errstr);
```

For a streaming downstream HTTP/2 request, this error path can reset or close the stream and synchronously dispose the request. The proxy generator is allocated from the request pool using:

```c
h2o_mem_alloc_shared(&req->pool, sizeof(*self), on_generator_dispose);
```

Request disposal therefore invokes `on_generator_dispose`, which closes and frees the generator. After that, the original `on_body_piped` code still dereferences `self`.

The non-piped `on_body` path already contains the expected lifetime guard:

```c
int generator_disposed = 0;
self->generator_disposed = &generator_disposed;
on_body_on_close(self, errstr);
if (!generator_disposed)
    self->generator_disposed = NULL;
```

The piped path lacked this guard.

A practical trigger is an attacker-controlled upstream backend sending response headers for a large plaintext HTTP/1 response so pipe mode is selected, then prematurely closing the response while the downstream client request body is still streaming.

## Why This Is A Real Bug

The code itself establishes that `on_body_on_close` may dispose `self`: the non-piped `on_body` callback explicitly installs and checks `generator_disposed` around the same function call.

`on_body_piped` performs the same hazardous call without the guard, then immediately reads fields from `self` and may pass `self` into `do_send_from_pipe`. If disposal occurred, those are use-after-free accesses.

This is not only theoretical: the reproduced scenario confirms that a streaming downstream request body plus an upstream piped response error can reach the disposing `proceed_req` path.

## Fix Requirement

Mirror the `on_body` lifetime guard in `on_body_piped`:

- Add a local `generator_disposed` flag.
- Assign `self->generator_disposed` before calling `on_body_on_close`.
- Clear `self->generator_disposed` only if the generator was not disposed.
- Do not access `self` after `on_body_on_close` if `generator_disposed` was set.

## Patch Rationale

The patch reuses the existing disposal notification mechanism already implemented for the non-piped response path. This keeps behavior consistent across body delivery modes and prevents post-disposal dereferences in `on_body_piped`.

The final send-from-pipe step is now skipped when `on_body_on_close` caused generator disposal.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/core/proxy.c b/lib/core/proxy.c
index 4cfbc66c9..18a35fb00 100644
--- a/lib/core/proxy.c
+++ b/lib/core/proxy.c
@@ -472,6 +472,7 @@ static int on_body(h2o_httpclient_t *client, const char *errstr, h2o_header_t *t
 
 static int on_body_piped(h2o_httpclient_t *client, const char *errstr, h2o_header_t *trailers, size_t num_trailers)
 {
+    int generator_disposed = 0;
     struct rp_generator_t *self = client->data;
 
     self->body_bytes_read = client->bytes_read.body;
@@ -482,9 +483,13 @@ static int on_body_piped(h2o_httpclient_t *client, const char *errstr, h2o_heade
         self->src_req->res.trailers = (h2o_headers_t){trailers, num_trailers, num_trailers};
     }
 
-    if (errstr != NULL)
+    if (errstr != NULL) {
+        self->generator_disposed = &generator_disposed;
         on_body_on_close(self, errstr);
-    if (!self->sending.inflight && !self->pipe_sender.inflight)
+        if (!generator_disposed)
+            self->generator_disposed = NULL;
+    }
+    if (!generator_disposed && !self->sending.inflight && !self->pipe_sender.inflight)
         do_send_from_pipe(self);
 
     return 0;
```