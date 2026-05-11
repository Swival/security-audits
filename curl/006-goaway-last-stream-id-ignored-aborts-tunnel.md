# GOAWAY last_stream_id ignored aborts tunnel

## Classification

Denial of service / protocol-correctness, low-to-medium severity. Confidence: certain.

## Affected Locations

- `lib/cf-h2-proxy.c:482` (`proxy_h2_on_frame_recv` GOAWAY case)
- `lib/cf-h2-proxy.c:1186` (`tunnel_recv` validity check)

## Summary

The HTTP/2 proxy CONNECT tunnel aborts as soon as the proxy sends a GOAWAY frame, even when the GOAWAY's `last_stream_id` still covers the tunnel stream. The receive-side handler sets `ctx->rcvd_goaway = TRUE` but never copies `frame->goaway.last_stream_id` into `ctx->last_stream_id`, which therefore remains at its zero-initialized value. Tunnel receive logic then treats any positive tunnel stream id as out of range and returns `CURLE_RECV_ERROR`.

The practical effect is that any GOAWAY, including the benign graceful-shutdown signal used by proxies announcing planned restart, terminates active CONNECT tunnels. A malicious proxy can use the same path as a one-shot tunnel abort.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- The client uses an HTTP/2 proxy CONNECT tunnel.
- The HTTP/2 proxy peer is attacker-controlled or malicious.
- The CONNECT stream has already been established with a positive stream id.

## Proof

- `proxy_h2_on_frame_recv` handles connection-level frames on stream id `0`.
- For `NGHTTP2_GOAWAY`, it sets `ctx->rcvd_goaway = TRUE`.
- Before the patch, it did not store `frame->goaway.last_stream_id`.
- `ctx->last_stream_id` therefore remained `0`.
- After CONNECT establishment, `ctx->tunnel.stream_id` is positive.
- A later `tunnel_recv` with no buffered tunnel data evaluates:

```c
ctx->rcvd_goaway && ctx->last_stream_id < ctx->tunnel.stream_id
```

- Because `last_stream_id` is still `0`, the condition is true for any established positive tunnel stream.
- The tunnel receive path returns `CURLE_RECV_ERROR`, even when the proxy's GOAWAY `last_stream_id` covers the CONNECT stream and the stream remains valid.

## Why This Is A Real Bug

HTTP/2 GOAWAY permits streams with identifiers less than or equal to `last_stream_id` to remain valid. The implementation already attempts to enforce that rule in `tunnel_recv`, but the comparison uses stale zero state because the received GOAWAY value is never stored. This creates an attacker-triggered protocol-state mismatch: a valid tunnel stream is treated as invalid solely because any GOAWAY was received.

## Fix Requirement

Store `frame->goaway.last_stream_id` when processing `NGHTTP2_GOAWAY`, and continue comparing the tunnel stream id against the recorded value.

## Patch Rationale

The patch copies the authoritative GOAWAY `last_stream_id` from the received nghttp2 frame into `ctx->last_stream_id` at the same point where `ctx->rcvd_goaway` is set. This makes the existing receive-side validity check operate on the peer-provided stream boundary instead of the zero-initialized default.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/cf-h2-proxy.c b/lib/cf-h2-proxy.c
index a0c5b14321..aab8516495 100644
--- a/lib/cf-h2-proxy.c
+++ b/lib/cf-h2-proxy.c
@@ -481,6 +481,7 @@ static int proxy_h2_on_frame_recv(nghttp2_session *session,
       break;
     case NGHTTP2_GOAWAY:
       ctx->rcvd_goaway = TRUE;
+      ctx->last_stream_id = frame->goaway.last_stream_id;
       break;
     default:
       break;
```