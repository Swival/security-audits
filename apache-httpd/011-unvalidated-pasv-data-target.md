# Unvalidated PASV Data Target

## Classification

High severity trust-boundary violation.

Confidence: certain.

## Affected Locations

`modules/proxy/mod_proxy_ftp.c:1405`

Primary vulnerable flow:

- `modules/proxy/mod_proxy_ftp.c:1491`
- `modules/proxy/mod_proxy_ftp.c:1523`
- `modules/proxy/mod_proxy_ftp.c:1531`

## Summary

The FTP proxy trusted the host octets returned in a remote server’s PASV `227` response. When EPSV was unavailable, an FTP server could return an arbitrary IPv4 address and port in PASV data, causing the proxy to open a TCP data connection to that attacker-selected target.

The patch changes PASV handling to ignore the PASV-provided host and connect only to the existing FTP control peer address with the PASV-provided port.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- The proxy handles an FTP URL.
- The remote FTP server returns a PASV `227` reply.
- EPSV is unavailable, rejected, or otherwise not used, causing fallback to PASV.

## Proof

`ftpmessage` is populated from the remote FTP control channel by `proxy_ftp_command`.

In the PASV branch, the code parses attacker-controlled address and port components from that message:

```c
sscanf(pstr, "%d,%d,%d,%d,%d,%d", &h3, &h2, &h1, &h0, &p1, &p0)
```

The original implementation then converted those untrusted host octets into a socket address:

```c
apr_sockaddr_info_get(&pasv_addr,
                      apr_psprintf(p, "%d.%d.%d.%d", h3, h2, h1, h0),
                      backend->addr->family, pasvport, 0, p);
```

It then connected the proxy data socket to that address:

```c
apr_socket_connect(data_sock, pasv_addr);
```

There was no check that the PASV host matched the FTP control connection peer, and the code did not reuse the already-established peer address.

A malicious FTP server could reply with:

```text
227 Entering Passive Mode (10,0,0,5,31,144)
```

This directs the proxy to connect to `10.0.0.5:8080`, assuming that target is reachable from the proxy host.

## Why This Is A Real Bug

The PASV response crosses a trust boundary: it is supplied by the remote FTP server but controls a new outbound connection made by the proxy.

Because the original code used the PASV host literally, an FTP server reached by the proxy could make the proxy initiate TCP connections to arbitrary IPv4 addresses and ports reachable from the proxy environment. This enables internal reachability probing and can expose data from services that send banners or other first-response data once the proxy reads from the data socket.

EPSV handling already follows the safer model: it uses the control connection peer address and only applies the server-supplied port. PASV lacked equivalent protection.

## Fix Requirement

PASV handling must not allow the remote FTP server to select an arbitrary data connection host.

Acceptable fixes are:

- Ignore the PASV host and connect to the control connection peer using the PASV port.
- Or explicitly require the PASV host to equal the control connection peer before connecting.

## Patch Rationale

The patch implements the safer EPSV-style behavior for PASV:

- Retrieves the actual FTP control peer with `apr_socket_addr_get(&remote_addr, APR_REMOTE, sock)`.
- Copies that peer address into `pasv_addr`.
- Replaces only the port with the parsed PASV port.
- Creates the data socket using `pasv_addr.family`.
- Connects to `&pasv_addr` rather than resolving and connecting to the PASV-provided host octets.

This preserves passive FTP data connection behavior while removing attacker control over the destination host.

The parsed PASV host octets remain syntactically consumed but are no longer trusted as the connection target.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/proxy/mod_proxy_ftp.c b/modules/proxy/mod_proxy_ftp.c
index 0e9c9b2..2c8a968 100644
--- a/modules/proxy/mod_proxy_ftp.c
+++ b/modules/proxy/mod_proxy_ftp.c
@@ -1491,14 +1491,29 @@ static int proxy_ftp_handler(request_rec *r, proxy_worker *worker,
             if (pstr != NULL && (sscanf(pstr,
                  "%d,%d,%d,%d,%d,%d", &h3, &h2, &h1, &h0, &p1, &p0) == 6)) {
 
-                apr_sockaddr_t *pasv_addr;
+                apr_sockaddr_t *remote_addr, pasv_addr;
                 apr_port_t pasvport = (p1 << 8) + p0;
                 ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01044)
-                              "PASV contacting host %d.%d.%d.%d:%d",
-                              h3, h2, h1, h0, pasvport);
+                              "PASV contacting remote host on port %d",
+                              pasvport);
 
-                if ((rv = apr_socket_create(&data_sock, backend->addr->family,
-                                            SOCK_STREAM, 0, r->pool)) != APR_SUCCESS) {
+                rv = apr_socket_addr_get(&remote_addr, APR_REMOTE, sock);
+                if (rv == APR_SUCCESS) {
+                    pasv_addr = *remote_addr;
+                    pasv_addr.port = pasvport;
+#if APR_HAVE_IPV6
+                    if (pasv_addr.family == APR_INET6) {
+                        pasv_addr.sa.sin6.sin6_port = htons(pasvport);
+                    }
+                    else
+#endif
+                    {
+                        pasv_addr.sa.sin.sin_port = htons(pasvport);
+                    }
+                    rv = apr_socket_create(&data_sock, pasv_addr.family,
+                                           SOCK_STREAM, 0, r->pool);
+                }
+                if (rv != APR_SUCCESS) {
                     ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01045)
                                   "error creating PASV socket");
                     proxy_ftp_cleanup(r, backend);
@@ -1520,20 +1535,12 @@ static int proxy_ftp_handler(request_rec *r, proxy_worker *worker,
                 }
 
                 /* make the connection */
-                err = apr_sockaddr_info_get(&pasv_addr, apr_psprintf(p, "%d.%d.%d.%d",
-                                                                     h3, h2, h1, h0),
-                                            backend->addr->family, pasvport, 0, p);
-                if (APR_SUCCESS != err) {
-                    return ftp_proxyerror(r, backend, HTTP_BAD_GATEWAY,
-                                          apr_pstrcat(p, "DNS lookup failure for: ",
-                                                      connectname, NULL));
-                }
-                rv = apr_socket_connect(data_sock, pasv_addr);
+                rv = apr_socket_connect(data_sock, &pasv_addr);
                 if (rv != APR_SUCCESS) {
                     ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01048)
-                                  "PASV attempt to connect to %pI failed - Firewall/NAT?", pasv_addr);
+                                  "PASV attempt to connect to %pI failed - Firewall/NAT?", &pasv_addr);
                     return ftp_proxyerror(r, backend, HTTP_BAD_GATEWAY, apr_psprintf(r->pool,
-                                                                           "PASV attempt to connect to %pI failed - firewall/NAT?", pasv_addr));
+                                                                           "PASV attempt to connect to %pI failed - firewall/NAT?", &pasv_addr));
                 }
                 else {
                     connect = 1;
```