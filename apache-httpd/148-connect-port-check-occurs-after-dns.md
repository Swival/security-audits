# CONNECT Port Authorization Occurs After DNS Resolution

## Classification

Validation gap, medium severity. Confidence: certain.

## Affected Locations

`modules/proxy/mod_proxy_connect.c:205`

## Summary

`mod_proxy_connect` resolves the CONNECT target hostname before enforcing `AllowCONNECT` port policy. A client that can issue CONNECT requests can force DNS lookups for attacker-chosen hostnames even when the requested port is disallowed and the request will ultimately be rejected.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

## Preconditions

A client can send a CONNECT request for a blocked port with an attacker-chosen hostname.

## Proof

In `proxy_connect_handler()`, the CONNECT request URL is parsed into `uri.hostname` and `uri.port`. The handler then assigns:

```c
connectname = proxyname ? proxyname : uri.hostname;
connectport = proxyname ? proxyport : uri.port;
```

It next calls DNS resolution:

```c
rv = apr_sockaddr_info_get(&nexthop, connectname, APR_UNSPEC,
                           connectport, 0, p);
```

Only after this lookup and the proxy block check does the handler enforce the CONNECT port policy:

```c
if (!allowed_port(c_conf, uri.port)) {
    return ap_proxyerror(r, HTTP_FORBIDDEN,
                         "Connect to remote machine blocked");
}
```

Therefore every handled CONNECT request reaches DNS resolution before disallowed ports are rejected.

## Why This Is A Real Bug

`AllowCONNECT` and the default CONNECT port policy are intended to reject unauthorized CONNECT destinations. Because hostname resolution occurs first, the rejected request still causes an externally observable DNS side effect. An unauthenticated or proxy-authorized client can repeatedly request blocked ports with controlled hostnames and induce resolver traffic that should have been prevented by the port authorization check.

## Fix Requirement

Check `allowed_port(c_conf, uri.port)` immediately after parsing and logging the CONNECT host and port, before assigning the next hop and before calling `apr_sockaddr_info_get()`.

## Patch Rationale

The patch moves the existing port authorization check from after DNS resolution to immediately after URI parsing. This preserves the same rejection behavior and error response while preventing DNS resolution and later processing for disallowed CONNECT ports.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/proxy/mod_proxy_connect.c b/modules/proxy/mod_proxy_connect.c
index 5a68135..a316152 100644
--- a/modules/proxy/mod_proxy_connect.c
+++ b/modules/proxy/mod_proxy_connect.c
@@ -196,6 +196,12 @@ static int proxy_connect_handler(request_rec *r, proxy_worker *worker,
     ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01019)
                   "connecting %s to %s:%d", url, uri.hostname, uri.port);
 
+    /* Check if it is an allowed port */
+    if (!allowed_port(c_conf, uri.port)) {
+        return ap_proxyerror(r, HTTP_FORBIDDEN,
+                             "Connect to remote machine blocked");
+    }
+
     /* Determine host/port of next hop; from request URI or of a proxy. */
     connectname = proxyname ? proxyname : uri.hostname;
     connectport = proxyname ? proxyport : uri.port;
@@ -222,12 +228,6 @@ static int proxy_connect_handler(request_rec *r, proxy_worker *worker,
                   "connecting to remote proxy %s on port %d",
                   connectname, connectport);
 
-    /* Check if it is an allowed port */
-    if (!allowed_port(c_conf, uri.port)) {
-        return ap_proxyerror(r, HTTP_FORBIDDEN,
-                             "Connect to remote machine blocked");
-    }
-
     /*
      * Step Two: Make the Connection
      *
```