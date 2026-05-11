# Active FTP Accepts First Inbound Peer

## Classification

Authentication bypass, medium severity.

Confidence: certain.

## Affected Locations

- `lib/cf-socket.c:2026` (`cf_tcp_accept_connect`)
- `lib/cf-socket.c:2082` / `:2085` (`CURL_ACCEPT4` / `CURL_ACCEPT` first inbound peer)
- `lib/cf-socket.c:2118` (`cf_tcp_set_accepted_remote_ip` records peer after replace)

## Summary

The active FTP data-channel accept path accepted the first inbound TCP connection to the client's listening data port without verifying that the peer was the FTP server. A reachable attacker could connect before the real server and become the data-channel peer.

For uploads, this could disclose uploaded file contents to the attacker. For downloads or listings, this could allow attacker-controlled data injection into the transfer.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

The finding was reproduced from source inspection and patched in `005-active-ftp-accepts-first-inbound-peer.patch`.

## Preconditions

- The client uses active FTP.
- An attacker can reach the client's active FTP listening data port.
- The attacker connects before the legitimate FTP server data connection arrives.

## Proof

`Curl_conn_tcp_listen_set` installs `Curl_cft_tcp_accept` for the active FTP listening socket. `cf_tcp_accept_connect` polls the listening socket and, when `CURL_CSELECT_IN` is set, calls `accept` or `accept4` on the first pending TCP connection.

After accept succeeds, the old listening socket is closed, `ctx->sock` is replaced with the accepted socket, and the connection is marked accepted, active, and connected. Only afterward, `cf_tcp_set_accepted_remote_ip` records the peer address using `getpeername()`.

The recorded peer address is not compared against the FTP control peer or any expected server address. The accepted socket is then used as the FTP data channel by the upload/download setup in `lib/ftp.c`.

## Why This Is A Real Bug

Active FTP expects the server to initiate the data connection back to the client. The vulnerable code treats reachability to the client data port as sufficient authorization.

Because the first pending TCP peer is accepted unconditionally, an attacker who wins the connection race becomes the data-channel peer. This violates the expected FTP server binding and creates practical confidentiality and integrity impact for active FTP transfers.

Optional `CURLSOCKTYPE_ACCEPT` callbacks or protected FTPS data channels can mitigate specific deployments, but the default active FTP accept path has no peer verification.

## Fix Requirement

Reject accepted data-channel sockets whose peer IP address does not match the expected FTP server address.

The rejection must occur before the accepted socket replaces the listening socket and before the connection is marked active or connected.

## Patch Rationale

The patch adds `cf_tcp_peer_ip_matches`, which compares the accepted peer socket address against the expected remote address from `Curl_conn_get_remote_addr(data, FIRSTSOCKET)`.

`cf_tcp_accept_connect` now validates the address returned by `accept` or `accept4` before continuing. If the peer IP is unexpected, the accepted socket is closed, an informational message is emitted, and the function returns `CURLE_OK` so the listener can continue waiting for the legitimate server connection.

This preserves active FTP behavior while preventing an arbitrary first inbound peer from becoming the data channel.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/cf-socket.c b/lib/cf-socket.c
index fc99ff39ed..0e81d85790 100644
--- a/lib/cf-socket.c
+++ b/lib/cf-socket.c
@@ -2023,6 +2023,30 @@ static void cf_tcp_set_accepted_remote_ip(struct Curl_cfilter *cf,
 #endif
 }
 
+static bool cf_tcp_peer_ip_matches(const struct sockaddr *peer,
+                                   const struct Curl_sockaddr_ex *expected)
+{
+  if(!expected || (peer->sa_family != expected->family))
+    return FALSE;
+
+  switch(peer->sa_family) {
+  case AF_INET:
+    return !memcmp(&((const struct sockaddr_in *)(const void *)peer)->sin_addr,
+                   &((const struct sockaddr_in *)(const void *)
+                     &expected->curl_sa_addr)->sin_addr,
+                   sizeof(struct in_addr));
+#ifdef USE_IPV6
+  case AF_INET6:
+    return !memcmp(&((const struct sockaddr_in6 *)(const void *)peer)->sin6_addr,
+                   &((const struct sockaddr_in6 *)(const void *)
+                     &expected->curl_sa_addr)->sin6_addr,
+                   sizeof(struct in6_addr));
+#endif
+  default:
+    return FALSE;
+  }
+}
+
 static CURLcode cf_tcp_accept_connect(struct Curl_cfilter *cf,
                                       struct Curl_easy *data,
                                       bool *done)
@@ -2090,6 +2114,12 @@ static CURLcode cf_tcp_accept_connect(struct Curl_cfilter *cf,
           curlx_strerror(SOCKERRNO, errbuf, sizeof(errbuf)));
     return CURLE_FTP_ACCEPT_FAILED;
   }
+  if(!cf_tcp_peer_ip_matches((struct sockaddr *)&add,
+                             Curl_conn_get_remote_addr(data, FIRSTSOCKET))) {
+    infof(data, "Data connection from unexpected server rejected");
+    Curl_socket_close(data, cf->conn, s_accepted);
+    return CURLE_OK;
+  }
 #ifndef HAVE_ACCEPT4
 #ifdef HAVE_FCNTL
   if(fcntl(s_accepted, F_SETFD, FD_CLOEXEC) < 0) {
```