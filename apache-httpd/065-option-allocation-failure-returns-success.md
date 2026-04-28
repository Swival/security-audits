# Option Allocation Failure Returns Success

## Classification

Error-handling bug; medium severity; confidence certain.

## Affected Locations

`modules/http2/h2_session.c:1013`

## Summary

`h2_session_create()` returns `APR_SUCCESS` when `nghttp2_option_new()` fails after callback initialization succeeds. The function has already stored a session pointer in `*psession`, then destroys the pool that owns that session, leaving callers with a stale pointer that they treat as valid.

## Provenance

Verified by reproduced finding from Swival Security Scanner: https://swival.dev

## Preconditions

`nghttp2_option_new()` fails after `init_callbacks()` succeeds.

## Proof

`h2_session_create()` stores `session` in `*psession` before later initialization completes. When `init_callbacks()` succeeds, `status` remains `APR_SUCCESS`. If `nghttp2_option_new()` returns nonzero, the error branch logs `APR_EGENERAL`, destroys `pool`, and returns `status`.

Because `status` is still `APR_SUCCESS`, callers can enter their success path while `*psession` still points to memory allocated from the destroyed session pool.

The reproduced path confirms practical use-after-free:

- `*psession` is set to `session` at `modules/http2/h2_session.c:950`.
- `session` is allocated from `pool` at `modules/http2/h2_session.c:943`.
- On `nghttp2_option_new()` failure, `pool` is destroyed and the function returns `status` at `modules/http2/h2_session.c:1028`.
- `h2_c1_setup()` treats `APR_SUCCESS` as success at `modules/http2/h2_c1.c:102`.
- `h2_c1_setup()` assigns the freed session into the connection context at `modules/http2/h2_c1.c:107`.
- `h2_conn_ctx_assign_session()` dereferences the freed session and uses `session->pool` in `apr_psprintf()` at `modules/http2/h2_conn_ctx.c:71`.

## Why This Is A Real Bug

The failing branch performs cleanup consistent with an initialization failure but returns a success code. That creates an inconsistent API result: the status says creation succeeded, while the returned session object has already been freed. The reproduced caller chain shows this is not theoretical; the stale pointer is immediately dereferenced on the normal success path.

## Fix Requirement

Return a non-success APR status after destroying the pool when `nghttp2_option_new()` fails, such as `APR_EGENERAL` or `APR_ENOMEM`.

## Patch Rationale

Returning `APR_EGENERAL` matches the status already used in the error log for this failure. It prevents callers from treating session creation as successful and avoids using `*psession` after its backing pool has been destroyed.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/http2/h2_session.c b/modules/http2/h2_session.c
index 21ede5c..53607a2 100644
--- a/modules/http2/h2_session.c
+++ b/modules/http2/h2_session.c
@@ -1026,7 +1026,7 @@ apr_status_t h2_session_create(h2_session **psession, conn_rec *c, request_rec *
                       APLOGNO(02928) "nghttp2_option_new: %s", 
                       nghttp2_strerror(rv));
         apr_pool_destroy(pool);
-        return status;
+        return APR_EGENERAL;
     }
     nghttp2_option_set_peer_max_concurrent_streams(options, (uint32_t)session->max_stream_count);
     /* We need to handle window updates ourself, otherwise we
```