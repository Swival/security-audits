# Unverified Active FTP Data Peer

## Classification

Trust-boundary violation; high severity; confidence certain.

## Affected Locations

`modules/proxy/mod_proxy_ftp.c:1927`

## Summary

When `mod_proxy_ftp` falls back to active FTP `PORT` mode, it accepts the first inbound data connection and streams that socket to the HTTP client without verifying that the accepted peer is the FTP control server. An attacker that can connect to the advertised active data endpoint first can supply the FTP response body.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- EPSV/PASV fail or are unsupported, causing active FTP `PORT` mode to be used.
- An attacker can learn or guess the proxy’s advertised active FTP data endpoint and connect before the expected FTP server data connection.
- The request path is reachable through `GET ftp://...` proxy handling.

## Proof

- `use_port` is set after a successful `PORT` command.
- In active mode, `apr_socket_accept(&data_sock, local_sock, r->pool)` accepts an arbitrary connecting peer into `data_sock`.
- No `APR_REMOTE` lookup or address comparison against the FTP control peer occurs before `data_sock` is wrapped as the transfer connection.
- The accepted socket is then read as the FTP data channel and its bytes are passed to the HTTP client as the response body.
- Reproduction confirmed that this path is reachable when passive setup fails and active FTP is selected.

## Why This Is A Real Bug

Active FTP data connections are expected to originate from the same FTP server reached over the control connection. The vulnerable code crosses that trust boundary by treating any accepted TCP peer as authoritative FTP data. A malicious or cooperating FTP control server can expose the `PORT` target to another peer or withhold its own data connection, letting the other peer win the accept race and inject arbitrary response content.

## Fix Requirement

After accepting an active FTP data connection, retrieve the accepted socket’s remote address and verify it matches the remote address of the FTP control socket before reading or streaming any data. Reject and close mismatched data sockets.

## Patch Rationale

The patch adds an address verification step immediately after `apr_socket_accept` succeeds in the active `PORT` path. It compares:

- `APR_REMOTE` from `data_sock`, the accepted data connection peer.
- `APR_REMOTE` from `sock`, the FTP control connection peer.

If address retrieval fails or the peers differ, the patch logs the mismatch, closes `data_sock`, cleans up the backend FTP connection, and returns `HTTP_BAD_GATEWAY`. This prevents untrusted third-party connections from becoming the FTP data stream.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/proxy/mod_proxy_ftp.c b/modules/proxy/mod_proxy_ftp.c
index 0e9c9b2..5bf5419 100644
--- a/modules/proxy/mod_proxy_ftp.c
+++ b/modules/proxy/mod_proxy_ftp.c
@@ -1923,6 +1923,8 @@ static int proxy_ftp_handler(request_rec *r, proxy_worker *worker,
 
     /* wait for connection */
     if (use_port) {
+        apr_sockaddr_t *data_addr, *ctrl_addr;
+
         for (;;) {
             rv = apr_socket_accept(&data_sock, local_sock, r->pool);
             if (APR_STATUS_IS_EINTR(rv)) {
@@ -1938,6 +1940,16 @@ static int proxy_ftp_handler(request_rec *r, proxy_worker *worker,
                 return HTTP_BAD_GATEWAY;
             }
         }
+        if (apr_socket_addr_get(&data_addr, APR_REMOTE, data_sock) != APR_SUCCESS
+                || apr_socket_addr_get(&ctrl_addr, APR_REMOTE, sock) != APR_SUCCESS
+                || !apr_sockaddr_equal(data_addr, ctrl_addr)) {
+            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(10240)
+                          "data connection peer does not match control connection peer");
+            apr_socket_close(data_sock);
+            data_sock = NULL;
+            proxy_ftp_cleanup(r, backend);
+            return HTTP_BAD_GATEWAY;
+        }
     }
 
     /* the transfer socket is now open, create a new connection */
```