# Missing Busy/Ready Field Check Before atoi

## Classification

Validation gap, medium severity.

## Affected Locations

`modules/cluster/mod_heartmonitor.c:779`

## Summary

The HTTP heartbeat POST handler parses request-body parameters and passes `busy` and `ready` directly to `atoi` without verifying that either field exists. If a POST body omits `busy`, `apr_table_get(tbl, "busy")` returns `NULL`, causing `atoi(NULL)`. If `busy` is present but `ready` is absent, the same issue occurs for `ready`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The heartbeat handler receives a POST request.
- The POST body is missing the `busy` parameter, or contains `busy` but is missing `ready`.

## Proof

The handler accepts POST requests for the `heartbeat` handler, reads up to `MAX_MSG_LEN` bytes from the request body, flattens the brigade into `buf`, and parses it with `qs_to_table`.

`qs_to_table` inserts only parameters present in the query-string-style body. Missing keys are not added to the APR table.

Before the patch, `hm_handler` then executed:

```c
hmserver.busy = atoi(apr_table_get(tbl, "busy"));
hmserver.ready = atoi(apr_table_get(tbl, "ready"));
```

When `busy` is absent, `apr_table_get(tbl, "busy")` returns `NULL`, and `NULL` is passed to `atoi`. When `ready` is absent, `apr_table_get(tbl, "ready")` returns `NULL`, and `NULL` is passed to `atoi`.

`atoi(NULL)` is undefined behavior and commonly crashes inside libc by dereferencing the null pointer. This is reachable for any heartbeat POST before `hm_update_stat` runs or a response is sent.

## Why This Is A Real Bug

The UDP heartbeat path already requires `v`, `busy`, and `ready` before parsing numeric values, but the HTTP POST handler did not apply equivalent validation. The POST handler trusts optional table lookups as mandatory fields and immediately parses them as integers.

Because APR table lookup returns `NULL` for absent keys, the failure is not theoretical: a malformed heartbeat POST lacking `busy` or `ready` reaches `atoi(NULL)` directly.

## Fix Requirement

Require both `busy` and `ready` parameters before calling `atoi`. If either parameter is absent, return `HTTP_BAD_REQUEST`.

## Patch Rationale

The patch adds a mandatory-field check immediately after request-body parsing and before any numeric conversion:

```c
if (apr_table_get(tbl, "busy") == NULL ||
    apr_table_get(tbl, "ready") == NULL) {
    return HTTP_BAD_REQUEST;
}
```

This prevents `NULL` values from reaching `atoi` while preserving existing behavior for valid heartbeat POST bodies. It also aligns the HTTP POST path with the UDP heartbeat path’s validation model for required heartbeat fields.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/cluster/mod_heartmonitor.c b/modules/cluster/mod_heartmonitor.c
index 68db585..dabecf6 100644
--- a/modules/cluster/mod_heartmonitor.c
+++ b/modules/cluster/mod_heartmonitor.c
@@ -772,6 +772,10 @@ static int hm_handler(request_rec *r)
     buf[len] = '\0';
     tbl = apr_table_make(r->pool, 10);
     qs_to_table(buf, tbl, r->pool);
+    if (apr_table_get(tbl, "busy") == NULL ||
+        apr_table_get(tbl, "ready") == NULL) {
+        return HTTP_BAD_REQUEST;
+    }
     apr_sockaddr_ip_get(&ip, r->connection->client_addr);
     hmserver.ip = ip;
     hmserver.port = 80;
```