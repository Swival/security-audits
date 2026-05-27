# CONNECT-UDP listener binds all interfaces

## Classification

- Type: SSRF / unauthenticated tunnel exposure
- Severity: Low
- Confidence: Certain

The affected component is the `h2o-httpclient` CLI tool, not the H2O server daemon. Exposure is bounded by the duration of an interactive `h2o-httpclient -X` invocation by an authorized operator on the host.

## Affected Locations

- `src/httpclient.c:747`
- Function: `create_udp_socket`

## Summary

The `-X <local-udp-port>` CONNECT-UDP listener bound its UDP socket to `INADDR_ANY` (`0.0.0.0`). Any remote host able to reach that UDP port could send datagrams to the listener. Those datagrams were then forwarded into the user's active CONNECT-UDP tunnel without authentication or source restriction.

The patch changes the listener bind address to `INADDR_LOOPBACK` (`127.0.0.1`) by default, limiting access to local clients.

## Provenance

Verified and patched from a Swival security finding.

- Scanner: [Swival.dev Security Scanner](https://swival.dev)
- Finding title: `CONNECT-UDP listener binds all interfaces`
- Source location: `src/httpclient.c:747`

## Preconditions

- The user runs the client with `-X`.
- A CONNECT-UDP tunnel is active.
- An attacker can reach the victim host's UDP port selected by `-X`.

## Proof

The `-X` option parses a local UDP port and calls:

```c
udp_sock = create_udp_socket(ctx.loop, udp_port);
h2o_socket_read_start(udp_sock, tunnel_on_udp_sock_read);
```

Before the patch, `create_udp_socket` initialized the bind address as:

```c
sin.sin_addr.s_addr = htonl(0);
```

This is `INADDR_ANY`, causing the UDP listener to accept datagrams on all IPv4 interfaces.

When a datagram arrives, `tunnel_on_udp_sock_read` calls `recvmsg`, records the sender address in `udp_sock_remote_addr`, and forwards the received payload into the CONNECT-UDP tunnel:

```c
mess.msg_name = &udp_sock_remote_addr;
...
rret = recvmsg(h2o_socket_get_fd(sock), &mess, 0);
```

Then, if datagram forwarding is available:

```c
h2o_iovec_t datagram = h2o_iovec_init(buf, context_id_len + rret);
udp_write(client, &datagram, 1);
```

Otherwise it builds a Datagram Capsule and sends it through `client->write_req` via `input_on_read`.

The reverse path confirms attacker utility. `tunnel_on_udp_read` sends datagrams received from the CONNECT-UDP tunnel back to `udp_sock_remote_addr` using `sendmsg`, allowing the last external UDP sender to receive tunnel responses.

## Why This Is A Real Bug

The listener was intended as a local UDP ingress for the user's CONNECT-UDP tunnel, but binding to `0.0.0.0` exposed it to the network.

Under the stated preconditions, an unauthenticated remote attacker could:

- inject attacker-controlled UDP payloads into the user's CONNECT-UDP tunnel;
- cause traffic to be sent to the CONNECT-UDP target chosen by the user;
- receive responses from the tunnel if they are the last recorded UDP sender.

This is narrower than arbitrary target SSRF because the CONNECT-UDP destination is user-selected, but it is still a concrete unauthenticated network exposure of the user's tunnel.

## Fix Requirement

The `-X` UDP listener must not bind to all interfaces by default.

Acceptable fixes include:

- binding the listener to loopback by default; or
- requiring an explicit bind address when non-loopback exposure is desired.

## Patch Rationale

The patch changes:

```c
sin.sin_addr.s_addr = htonl(0);
```

to:

```c
sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
```

This preserves the local UDP listener behavior for local clients while preventing remote hosts from reaching the `-X` listener through external interfaces.

## Residual Risk

None

## Patch

```diff
diff --git a/src/httpclient.c b/src/httpclient.c
index bf1ea38f8..5037b4be4 100644
--- a/src/httpclient.c
+++ b/src/httpclient.c
@@ -735,7 +735,7 @@ h2o_socket_t *create_udp_socket(h2o_loop_t *loop, uint16_t port)
         exit(EXIT_FAILURE);
     }
     sin.sin_family = AF_INET;
-    sin.sin_addr.s_addr = htonl(0);
+    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
     sin.sin_port = htons(port);
     if (bind(fd, (void *)&sin, sizeof(sin)) != 0) {
         perror("failed to bind bind UDP socket");
```