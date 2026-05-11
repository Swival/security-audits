# First TFTP Response Pins Spoofed Peer Address

## Classification

Information disclosure, medium severity.

## Affected Locations

`lib/tftp.c:1056` (`tftp_receive_packet` first-use pinning branch)

## Summary

The TFTP client accepted and pinned the source address of the first UDP response after sending an RRQ or WRQ without verifying that the response came from the originally connected server address. A network attacker able to race a valid first TFTP response could become the pinned peer and receive subsequent upload DATA packets.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Attacker can send a valid first TFTP response before the real server.
- Client is performing a TFTP transfer over UDP.
- For the demonstrated disclosure path, the client is uploading and the attacker races a valid ACK for block 0 or OACK.

## Proof

`tftp_send_first()` sends the initial RRQ or WRQ to `Curl_conn_get_remote_addr(data, FIRSTSOCKET)`.

Before the patch, `tftp_receive_packet()` used `recvfrom()` and, when `state->remote_pinned` was false, unconditionally copied the first received UDP source into `state->remote_addr`:

```c
state->remote_pinned = TRUE;
state->remote_addrlen = fromlen;
memcpy(&state->remote_addr, &remote_addr, fromlen);
```

For upload, an attacker can race a valid ACK for block 0. Because `state` is calloc-initialized, `state->block` starts at 0. `tftp_tx()` accepts the ACK, advances to block 1, reads upload data from the client, and sends the DATA packet to `state->remote_addr`.

At that point `state->remote_addr` is attacker-controlled, so uploaded file contents are sent to the spoofed peer. Later packets from the real server are rejected as coming from another address, but disclosure has already occurred.

## Why This Is A Real Bug

The code binds trust for the entire TFTP session to the first UDP packet source rather than to the server address used for the initial request. TFTP legitimately switches to a server-selected transfer port after the initial request, but it must not accept a first response from a different IP address. Without that check, an off-path or adjacent network attacker who can race UDP replies can redirect upload data to themselves.

## Fix Requirement

Only pin the first TFTP response if its source IP address matches the connected server address. After the peer is pinned, continue rejecting packets that do not match the pinned address and port.

## Patch Rationale

The patch changes the first-use pinning path in `tftp_receive_packet()` to compare the first response source address against `Curl_conn_get_remote_addr(data, FIRSTSOCKET)` before setting `state->remote_pinned`.

It compares:

- address family
- IPv4 address for `AF_INET`
- IPv6 address for `AF_INET6`
- IPv6 scope ID when available

If the first response does not match the original server address, the transfer fails with `CURLE_RECV_ERROR` and logs `Data received from another address`. This preserves TFTP’s expected behavior of allowing the server to reply from a different transfer port while preventing pinning to a different host.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/tftp.c b/lib/tftp.c
index 6cc672d447..5825b79df0 100644
--- a/lib/tftp.c
+++ b/lib/tftp.c
@@ -1054,6 +1054,42 @@ static CURLcode tftp_receive_packet(struct Curl_easy *data,
       }
     }
     else {
+      const struct Curl_sockaddr_ex *peer_addr =
+        Curl_conn_get_remote_addr(data, FIRSTSOCKET);
+      const struct sockaddr *from = (const struct sockaddr *)&remote_addr;
+      const struct sockaddr *peer;
+      bool same_addr = FALSE;
+      if(!peer_addr)
+        return CURLE_FAILED_INIT;
+      peer = &peer_addr->curl_sa_addr;
+      if(peer->sa_family == from->sa_family) {
+        switch(from->sa_family) {
+        case AF_INET: {
+          const struct sockaddr_in *from4 = (const void *)from;
+          const struct sockaddr_in *peer4 = (const void *)peer;
+          same_addr = !memcmp(&from4->sin_addr, &peer4->sin_addr,
+                              sizeof(from4->sin_addr));
+          break;
+        }
+#ifdef USE_IPV6
+        case AF_INET6: {
+          const struct sockaddr_in6 *from6 = (const void *)from;
+          const struct sockaddr_in6 *peer6 = (const void *)peer;
+          same_addr = !memcmp(&from6->sin6_addr, &peer6->sin6_addr,
+                              sizeof(from6->sin6_addr));
+#ifdef HAVE_SOCKADDR_IN6_SIN6_SCOPE_ID
+          same_addr = same_addr &&
+            (from6->sin6_scope_id == peer6->sin6_scope_id);
+#endif
+          break;
+        }
+#endif
+        }
+      }
+      if(!same_addr) {
+        failf(data, "Data received from another address");
+        return CURLE_RECV_ERROR;
+      }
       /* pin address on first use */
       state->remote_pinned = TRUE;
       state->remote_addrlen = fromlen;
```