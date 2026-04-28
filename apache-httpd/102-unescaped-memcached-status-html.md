# Unescaped Memcached Status HTML

## Classification

Medium severity vulnerability: stored/reflected HTML injection in the HTML `server-status` output.

## Affected Locations

`modules/cache/mod_socache_memcache.c:308`

## Summary

`mod_socache_memcache` prints `stats->version` from `apr_memcache_stats()` directly into the non-short HTML status page. If a memcached-compatible server returns an attacker-controlled version string, HTML or JavaScript is interpreted by clients viewing `server-status`.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- `mod_status` status page is enabled.
- A memcache socache user, such as `mod_cache_socache` or `mod_ssl`, is configured with the memcache provider.
- The memcached server, compatible endpoint, or network path can return an attacker-controlled `stats->version` value.
- A user views the non-short HTML status page rather than `?auto`.

## Proof

`apr_memcache_stats(ms, r->pool, &stats)` populates `stats->version` from memcached stats data.

In the non-short status branch, the value is inserted directly into HTML:

```c
ap_rprintf(r, "<b>Version:</b> <i>%s</i> [%u bits], PID: <i>%u</i>, Uptime: <i>%u hrs</i> <br />\n",
        stats->version , stats->pointer_size, stats->pid, stats->uptime/3600);
```

No `ap_escape_html()` or equivalent encoding is applied before insertion into `<i>%s</i>`. A version string such as:

```html
<script>alert(1)</script>
```

would render as active markup in the HTML status page.

The callback is reachable because the memcache socache provider binds `socache_mc_status` as its status callback, and status extension hooks are invoked by `mod_status` for the HTML status response.

## Why This Is A Real Bug

The vulnerable value crosses a trust boundary: it originates from a memcached stats response and is emitted into an HTML document. HTML context requires escaping of `<`, `>`, `&`, and quotes where applicable. Without escaping, attacker-controlled markup can execute in the browser of a `server-status` viewer.

The issue is limited by configuration and attacker control requirements, but under the stated preconditions it is directly exploitable.

## Fix Requirement

HTML-escape `stats->version` before passing it to `ap_rprintf()` in the non-short HTML status output.

## Patch Rationale

The patch applies `ap_escape_html(r->pool, stats->version)` at the only confirmed HTML insertion point for the memcached version string:

```diff
-                    stats->version , stats->pointer_size, stats->pid, stats->uptime/3600);
+                    ap_escape_html(r->pool, stats->version), stats->pointer_size, stats->pid, stats->uptime/3600);
```

This preserves the displayed version text while ensuring HTML metacharacters are encoded before reaching the client. The short status branch is not HTML-specific and was not part of the reproduced HTML injection path.

## Residual Risk

None

## Patch

`102-unescaped-memcached-status-html.patch`

```diff
diff --git a/modules/cache/mod_socache_memcache.c b/modules/cache/mod_socache_memcache.c
index f122ba4..7351a84 100644
--- a/modules/cache/mod_socache_memcache.c
+++ b/modules/cache/mod_socache_memcache.c
@@ -306,7 +306,7 @@ static void socache_mc_status(ap_socache_instance_t *ctx, request_rec *r, int fl
             continue;
         if (!(flags & AP_STATUS_SHORT)) {
             ap_rprintf(r, "<b>Version:</b> <i>%s</i> [%u bits], PID: <i>%u</i>, Uptime: <i>%u hrs</i> <br />\n",
-                    stats->version , stats->pointer_size, stats->pid, stats->uptime/3600);
+                    ap_escape_html(r->pool, stats->version), stats->pointer_size, stats->pid, stats->uptime/3600);
             ap_rprintf(r, "<b>Clients::</b> Structures: <i>%u</i>, Total: <i>%u</i>, Current: <i>%u</i> <br />\n",
                     stats->connection_structures, stats->total_connections, stats->curr_connections);
             ap_rprintf(r, "<b>Storage::</b> Total Items: <i>%u</i>, Current Items: <i>%u</i>, Bytes: <i>%" APR_UINT64_T_FMT "</i> <br />\n",
```