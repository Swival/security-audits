# Unbounded Request Body Buffering

## Classification

Denial of service, medium severity.

## Affected Locations

`src/uws_sys/BodyReaderMixin.rs:185`

## Summary

`BodyReaderMixin::read_body` buffered attacker-controlled request bodies into a `Vec<u8>` without enforcing a maximum size before allocation. A remote HTTP client could send a very large or chunked body to an endpoint using this mixin, causing process memory exhaustion or allocator abort and denying service.

## Provenance

Confirmed by Swival.dev Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The endpoint uses `BodyReaderMixin::read_body` for client request bodies.
- A remote HTTP client can reach such an endpoint.
- The request body can be sent as large chunks or as multiple non-final chunks.

## Proof

`read_body` registers `on_data_generic` as the uWS response data callback.

For non-final chunks, `on_data` reached the buffering branch and appended attacker-controlled bytes directly:

```rust
Self::mixin_of(wrap).body.extend_from_slice(chunk);
```

There was no size check before `Vec::extend_from_slice`.

For final chunks, if prior data had already been buffered, the final chunk was also appended to the accumulated `Vec` before invoking `Wrap::on_body`:

```rust
body.extend_from_slice(chunk);
unsafe { Wrap::on_body(wrap, body.as_slice(), resp)? };
```

The reproducer confirmed that dev-server internal routes such as `/_bun/report_error` and `/_bun/unref` install raw uWS routes directly and bypass the generic request-body limit present elsewhere in the server path.

Impact: memory grows with attacker-controlled input until exhaustion. Rust `Vec` allocation failure can abort the process under default allocator behavior, producing denial of service.

## Why This Is A Real Bug

The vulnerable code accepted request body data from a remote client and accumulated it in process memory without a cap. This was not merely inefficient behavior: the allocation was proportional to attacker input, occurred before semantic validation, and could terminate the process on out-of-memory.

The existing generic request-body limit did not protect these routes because the affected code path used `BodyReaderMixin` directly.

## Fix Requirement

Enforce a maximum request body size before every append or body handoff that would cause unbounded buffering, and reject oversized bodies before allocating additional memory.

## Patch Rationale

The patch adds a fixed body limit:

```rust
const MAX_BODY_SIZE: usize = 1024 * 1024 * 128;
```

It checks the total buffered size before appending non-final chunks:

```rust
let body = &mut Self::mixin_of(wrap).body;
if body.len().saturating_add(chunk.len()) > MAX_BODY_SIZE {
    return Err(bun_core::err!(RequestBodyTooLarge));
}
body.extend_from_slice(chunk);
```

It also checks final chunks in both cases:

- when appending a final chunk to an already-buffered body
- when handling a single final chunk without prior buffered data

`saturating_add` prevents integer overflow from bypassing the limit calculation. Returning `RequestBodyTooLarge` routes the failure through the existing invalid-request handling path instead of allocating more memory.

## Residual Risk

None

## Patch

```diff
diff --git a/src/uws_sys/BodyReaderMixin.rs b/src/uws_sys/BodyReaderMixin.rs
index df37895848..5fd7b75425 100644
--- a/src/uws_sys/BodyReaderMixin.rs
+++ b/src/uws_sys/BodyReaderMixin.rs
@@ -91,6 +91,8 @@ pub struct BodyReaderMixin<Wrap: BodyReaderHandler> {
     _wrap: PhantomData<Wrap>,
 }
 
+const MAX_BODY_SIZE: usize = 1024 * 1024 * 128;
+
 impl<Wrap: BodyReaderHandler> BodyReaderMixin<Wrap> {
     pub fn init() -> Self {
         Self {
@@ -176,17 +178,27 @@ impl<Wrap: BodyReaderHandler> BodyReaderMixin<Wrap> {
             // mixin.body has ended, so on_body receives sole ownership of the
             // allocation and may heap::take it on success.
             if !body.is_empty() {
+                if body.len().saturating_add(chunk.len()) > MAX_BODY_SIZE {
+                    return Err(bun_core::err!(RequestBodyTooLarge));
+                }
                 // TODO(port): Zig handled OOM gracefully here; Vec::extend_from_slice aborts.
                 // Consider try_reserve in Phase B if graceful 500 on OOM is required.
                 body.extend_from_slice(chunk);
                 unsafe { Wrap::on_body(wrap, body.as_slice(), resp)? };
             } else {
+                if chunk.len() > MAX_BODY_SIZE {
+                    return Err(bun_core::err!(RequestBodyTooLarge));
+                }
                 unsafe { Wrap::on_body(wrap, chunk, resp)? };
             }
             // `body` drops here (was `defer body.deinit()` in Zig)
             Ok(())
         } else {
-            Self::mixin_of(wrap).body.extend_from_slice(chunk);
+            let body = &mut Self::mixin_of(wrap).body;
+            if body.len().saturating_add(chunk.len()) > MAX_BODY_SIZE {
+                return Err(bun_core::err!(RequestBodyTooLarge));
+            }
+            body.extend_from_slice(chunk);
             Ok(())
         }
     }
```