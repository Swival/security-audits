# Unauthenticated QUIC Forwarded Header Spoofing

## Classification

- Type: Authentication bypass
- Severity: High
- Confidence: Certain

## Affected Locations

- `src/main.c:2466`
- `src/main.c`: `decode_quic_forwarded_header`
- `src/main.c`: `rewrite_forwarded_quic_datagram`
- `src/main.c`: `run_loop`
- `src/main.c`: `forwarded_quic_socket_on_read`
- `src/main.c`: `on_http3_accept`

## Summary

A public QUIC listener accepted H2O QUIC forwarded headers from any remote UDP client. The forwarded header carried attacker-controlled destination and source addresses and was parsed without authentication. When accepted, the server replaced the packet source address with the attacker-supplied value, causing retry, invalid-token, and other QUIC response paths to send packets to an arbitrary victim address.

The patch confines forwarded-header decoding to the private intra-process forwarded socket path and disables forwarded-header preprocessing on the public listener socket.

## Provenance

Found and reproduced by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- Public QUIC listener is enabled.

## Proof

`run_loop` initialized the public QUIC listener context with:

```c
h2o_quic_set_forwarding_context(&listeners[i].http3.ctx.super, 0, 4, forward_quic_packets,
                                rewrite_forwarded_quic_datagram);
```

This registered `rewrite_forwarded_quic_datagram` as the QUIC packet preprocessor for packets arriving on the public UDP listener.

`rewrite_forwarded_quic_datagram` calls `decode_quic_forwarded_header`. The decoded format checks only:

- magic byte `0x80`
- version `H2O_QUIC_FORWARDED_VERSION`
- encoded destination address
- encoded source address
- TTL

The adjacent code comment states authentication is still TODO:

```c
/**
 * encodes a forwarded header
 * TODO add authentication for inter-node forwarding
 */
```

On successful decode, `rewrite_forwarded_quic_datagram` strips the header and overwrites packet addressing:

```c
msg->msg_iov[0].iov_base += encapsulated.offset;
msg->msg_iov[0].iov_len -= encapsulated.offset;
*destaddr = encapsulated.destaddr;
*srcaddr = encapsulated.srcaddr;
*ttl = encapsulated.ttl;
```

`on_http3_accept` then uses this attacker-supplied `srcaddr` in response paths. For invalid tokens and retry, it calls:

```c
h2o_quic_send_datagrams(&ctx->super, srcaddr, destaddr, &vec, 1, 0);
```

`h2o_quic_send_datagrams` uses the first address argument as the UDP destination and the second as packet-info source address. Therefore a remote UDP client can send a datagram beginning with the forwarded-header magic/version and cause H2O to emit QUIC responses to an arbitrary victim UDP address of the same address family, sourced from the listener address/port.

## Why This Is A Real Bug

The forwarded-header format is intended for internal QUIC packet forwarding, but the public listener parsed it before authenticating the sender or restricting it to a private forwarding socket.

This gives any reachable remote UDP client a concrete reflection and source-spoofing primitive without requiring network-layer source-address spoofing. The attacker controls the forwarded `srcaddr`; server response paths trust that value and transmit packets to it.

## Fix Requirement

Forwarded QUIC headers must not be parsed on public UDP listener sockets unless they are authenticated. Acceptable fixes are:

- authenticate forwarded headers, or
- parse forwarded headers only on private forwarding sockets.

## Patch Rationale

The patch implements the second requirement.

The public QUIC listener is initialized with no preprocessing callback:

```c
h2o_quic_set_forwarding_context(&listeners[i].http3.ctx.super, 0, 4, forward_quic_packets, NULL);
```

The private forwarded socket read handler temporarily installs `rewrite_forwarded_quic_datagram` only while reading from the private forwarded socket:

```c
h2o_quic_preprocess_packet_cb preprocess_packet = ctx->http3.ctx.super.preprocess_packet;
ctx->http3.ctx.super.preprocess_packet = rewrite_forwarded_quic_datagram;
h2o_quic_read_socket(&ctx->http3.ctx.super, sock);
ctx->http3.ctx.super.preprocess_packet = preprocess_packet;
```

This preserves internal forwarding behavior while preventing unauthenticated forwarded-header parsing on the public listener.

## Residual Risk

The patch removes forwarded-header preprocessing from the public listener. Inter-process QUIC packet forwarding via the AF_UNIX socketpair (intra-node, between worker threads) still works because the private `forwarded_sock` reader temporarily re-installs the preprocess callback.

The undocumented experimental `quic-nodes` feature (see `t/60find-doc.t`) relies on inter-node forwarded packets arriving on the public UDP listener and therefore would stop functioning. Production deployments do not configure `quic-nodes`. A complete remediation that preserves inter-node forwarding requires authentication of forwarded headers (the in-tree `TODO add authentication for inter-node forwarding` comment acknowledges this).

## Patch

```diff
diff --git a/src/main.c b/src/main.c
index 42b3cfb13..4467a2919 100644
--- a/src/main.c
+++ b/src/main.c
@@ -4222,7 +4222,10 @@ static int rewrite_forwarded_quic_datagram(h2o_quic_ctx_t *h3ctx, struct msghdr
 static void forwarded_quic_socket_on_read(h2o_socket_t *sock, const char *err)
 {
     struct listener_ctx_t *ctx = sock->data;
+    h2o_quic_preprocess_packet_cb preprocess_packet = ctx->http3.ctx.super.preprocess_packet;
+    ctx->http3.ctx.super.preprocess_packet = rewrite_forwarded_quic_datagram;
     h2o_quic_read_socket(&ctx->http3.ctx.super, sock);
+    ctx->http3.ctx.super.preprocess_packet = preprocess_packet;
 }
 
 static void on_socketclose(void *data)
@@ -4515,8 +4518,7 @@ H2O_NORETURN static void *run_loop(void *_thread_index)
                                           conf.threads[thread_index].ctx.loop, listeners[i].sock, NULL, listener_config->quic.ctx,
                                           &conf.threads[thread_index].ctx.http3.next_cid, on_http3_accept, NULL,
                                           conf.globalconf.http3.use_gso);
-            h2o_quic_set_forwarding_context(&listeners[i].http3.ctx.super, 0, 4, forward_quic_packets,
-                                            rewrite_forwarded_quic_datagram);
+            h2o_quic_set_forwarding_context(&listeners[i].http3.ctx.super, 0, 4, forward_quic_packets, NULL);
             listeners[i].http3.ctx.accept_ctx = &listeners[i].accept_ctx;
             listeners[i].http3.ctx.send_retry = listener_config->quic.send_retry;
             listeners[i].http3.ctx.qpack = listener_config->quic.qpack;
```