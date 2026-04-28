# Per-Directory H2ProxyRequests Enables Server Forward Proxy

## Classification

Authorization flaw, medium severity.

## Affected Locations

`modules/http2/h2_config.c:1144`

## Summary

`H2ProxyRequests` was registered as an `OR_FILEINFO` directive, allowing it to be used from per-directory configuration such as `.htaccess` when FileInfo overrides are delegated. Because the directive writes to server-level `h2_config.proxy_requests` when no directory-specific storage exists for the setting, a delegated per-directory user could enable HTTP/2 forward-proxy handling beyond their directory scope.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- An administrator permits per-directory FileInfo overrides that can contain `H2ProxyRequests`.
- A delegated user can place or modify a per-directory configuration file such as `.htaccess`.
- HTTP/2 handling is active.
- Forward proxy impact requires mod_proxy forward proxying to be available; specifically, `ProxyRequests On` creates the forward worker in `modules/proxy/mod_proxy.c:3280`.

## Proof

`H2ProxyRequests` was registered with `OR_FILEINFO`:

```c
AP_INIT_TAKE1("H2ProxyRequests", h2_conf_set_proxy_requests, NULL,
              OR_FILEINFO, "Enables forward proxy requests via HTTP/2"),
```

When parsed from per-directory scope, `cmd->path` is set, so `CONFIG_CMD_SET` passes `dirconf` into `h2_config_seti`:

```c
#define CONFIG_CMD_SET(cmd,dir,var,val) \
    h2_config_seti(((cmd)->path? (dir) : NULL), h2_config_sget((cmd)->server), var, val)
```

`h2_config_seti` has directory cases for `H2_CONF_UPGRADE`, `H2_CONF_PUSH`, and `H2_CONF_EARLY_HINTS`, but no case for `H2_CONF_PROXY_REQUESTS`. The default branch sets `set_srv = 1`, causing the server-level setter to run:

```c
default:
    /* not handled in dir_conf */
    set_srv = 1;
    break;
```

`h2_srv_config_seti` then writes the server-wide field:

```c
case H2_CONF_PROXY_REQUESTS:
    H2_CONFIG_SET(conf, proxy_requests, val);
    break;
```

Reproduced behavior:

1. Administrator delegates FileInfo overrides to a directory.
2. Delegated user places `H2ProxyRequests On` in `.htaccess`.
3. A request that parses the `.htaccess` executes the directive.
4. The directive mutates the vhost/server `h2_config`.
5. Subsequent HTTP/2 requests handled by that process/server observe `proxy_requests = 1` globally.
6. With mod_proxy forward proxying available, the absolute URI synthesized by mod_http2 is consumed by `proxy_detect()` at `modules/proxy/mod_proxy.c:799`, which marks the request as `PROXYREQ_PROXY` at `modules/proxy/mod_proxy.c:807`.

## Why This Is A Real Bug

The directive is security-sensitive because it controls HTTP/2 forward proxy behavior. Its registration allowed delegated per-directory configuration to invoke it, but the implementation had no per-directory storage or enforcement for `H2_CONF_PROXY_REQUESTS`. Instead of remaining scoped to the directory, the setting fell through into the server configuration and persisted as server-wide state.

This violates Apache configuration scoping expectations: a user granted per-directory FileInfo override authority should not be able to mutate vhost/server-wide forward proxy behavior.

## Fix Requirement

`H2ProxyRequests` must not be accepted from per-directory configuration. It must be restricted to server/vhost configuration, or explicitly rejected when `cmd->path` is set.

## Patch Rationale

The patch changes the directive context from `OR_FILEINFO` to `RSRC_CONF`:

```diff
 AP_INIT_TAKE1("H2ProxyRequests", h2_conf_set_proxy_requests, NULL,
-              OR_FILEINFO, "Enables forward proxy requests via HTTP/2"),
+              RSRC_CONF, "Enables forward proxy requests via HTTP/2"),
```

This prevents `.htaccess` and other per-directory FileInfo contexts from invoking `H2ProxyRequests`. Server and vhost administrators can still configure the directive intentionally in resource/server configuration, preserving intended administrative functionality while removing delegated scope escalation.

## Residual Risk

None

## Patch

`063-per-directory-directive-enables-server-forward-proxy.patch`

```diff
diff --git a/modules/http2/h2_config.c b/modules/http2/h2_config.c
index 94fd8d2..07d10a8 100644
--- a/modules/http2/h2_config.c
+++ b/modules/http2/h2_config.c
@@ -1118,7 +1118,7 @@ const command_rec h2_cmds[] = {
     AP_INIT_TAKE2("H2EarlyHint", h2_conf_add_early_hint, NULL,
                    OR_FILEINFO|OR_AUTHCFG, "add a a 'Link:' header for a 103 Early Hints response."),
     AP_INIT_TAKE1("H2ProxyRequests", h2_conf_set_proxy_requests, NULL,
-                  OR_FILEINFO, "Enables forward proxy requests via HTTP/2"),
+                  RSRC_CONF, "Enables forward proxy requests via HTTP/2"),
     AP_INIT_TAKE1("H2WebSockets", h2_conf_set_websockets, NULL,
                   RSRC_CONF, "off to disable WebSockets over HTTP/2"),
     AP_END_CMD
```