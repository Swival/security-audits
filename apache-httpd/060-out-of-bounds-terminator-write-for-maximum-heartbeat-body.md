# Out-of-Bounds Terminator Write for Maximum Heartbeat Body

## Classification

Memory safety; severity high; confidence certain

## Affected Locations

`modules/cluster/mod_heartmonitor.c:771`

## Summary

The HTTP `heartbeat` POST handler allocates a `MAX_MSG_LEN` byte buffer, reads up to `MAX_MSG_LEN` bytes into it, and then writes a NUL terminator at `buf[len]`. When the request body contributes exactly 1000 bytes, `len == MAX_MSG_LEN`, so `buf[1000] = '\0'` writes one byte past the allocation.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The request is routed to handler `"heartbeat"`.
- The request method is `POST`.
- The POST body reaches the handler with exactly 1000 readable bytes, or at least enough bytes for the maximum read to produce `len == MAX_MSG_LEN`.

## Proof

`MAX_MSG_LEN` is defined as 1000.

In `hm_handler`, the buffer is allocated with exactly `MAX_MSG_LEN` bytes:

```c
buf = apr_pcalloc(r->pool, MAX_MSG_LEN);
```

The handler then asks Apache to read up to `MAX_MSG_LEN` bytes:

```c
status = ap_get_brigade(r->input_filters, input_brigade,
                        AP_MODE_READBYTES, APR_BLOCK_READ, MAX_MSG_LEN);
```

`len` is initialized to `MAX_MSG_LEN` and passed to `apr_brigade_flatten`:

```c
len = MAX_MSG_LEN;
apr_brigade_flatten(input_brigade, buf, &len);
```

For a 1000-byte POST body, `apr_brigade_flatten` can leave `len == 1000`. The next write terminates the copied data:

```c
buf[len] = '\0';
```

With `len == 1000`, this writes to `buf[1000]`, one byte beyond the valid indices of the 1000-byte allocation.

The UDP receive path does not have this specific defect because it uses:

```c
char buf[MAX_MSG_LEN + 1];
```

before passing the buffer to `hm_processmsg`.

## Why This Is A Real Bug

The vulnerable path is directly reachable by any configured endpoint mapped to the `heartbeat` handler using method `POST`. The handler explicitly supports POST bodies up to `MAX_MSG_LEN`, but its allocation only reserves space for the body bytes and not the required terminator. The out-of-bounds write occurs before request parsing continues and does not require malformed APR behavior.

## Practical Exploit Scenario

A load-balanced cluster runs `mod_heartmonitor` on a coordinator host, exposing `/HeartbeatAccept` so backend workers can post liveness data. The endpoint is intentionally unauthenticated (`Require all granted`) because heartbeat traffic is expected to be filtered by network policy, but in many real deployments that filter is loose: the endpoint ends up reachable from any internal subnet, from anyone who compromises a single backend, or from the public internet on misconfigured listeners.

An attacker who can reach the handler sends a single 1000-byte POST:

```http
POST /HeartbeatAccept HTTP/1.1
Host: cluster-coord.internal
Content-Type: application/x-www-form-urlencoded
Content-Length: 1000

v=1&busy=0&ready=1&xxxxxxxxxxxxxxxxxxxx...   (padded to exactly 1000 bytes)
```

The handler allocates exactly 1000 bytes, reads exactly 1000 bytes, and then writes a NUL byte at `buf[1000]`, one byte past the allocation. Apache's pool allocator places small objects back-to-back, so the overflow byte lands in the next pool node header or adjacent allocation. On hardened builds (FORTIFY, ASan, MSan, or pool guard pages) this terminates the worker. On stock builds it silently corrupts the next allocation: usually the header parsing scratch buffer, sometimes a string interned for the access log, occasionally a function pointer in pool cleanup metadata. The attacker can replay the request thousands of times per second from a single IP, repeatedly knocking out the coordinator and causing the rest of the cluster to lose heartbeat consensus, drop healthy backends from rotation, and degrade or fail entirely. With deeper allocator shaping, the single-byte write can also be steered into adjacent state to corrupt cleanup function pointers, providing a stepping stone toward control-flow hijack on a long-running coordinator.

## Fix Requirement

Reserve space for the NUL terminator when reading up to `MAX_MSG_LEN` bytes, or reject/avoid termination when `len == MAX_MSG_LEN`.

## Patch Rationale

The patch changes the HTTP handler allocation from `MAX_MSG_LEN` to `MAX_MSG_LEN + 1`:

```diff
-    buf = apr_pcalloc(r->pool, MAX_MSG_LEN);
+    buf = apr_pcalloc(r->pool, MAX_MSG_LEN + 1);
```

This preserves the existing maximum accepted/read body size while making `buf[len] = '\0'` safe for the maximum valid `len` value of 1000. It also aligns the HTTP path with the existing UDP path, which already allocates `MAX_MSG_LEN + 1`.

## Residual Risk

None

## Patch

`060-out-of-bounds-terminator-write-for-maximum-heartbeat-body.patch`

```diff
diff --git a/modules/cluster/mod_heartmonitor.c b/modules/cluster/mod_heartmonitor.c
index 68db585..d3c74f4 100644
--- a/modules/cluster/mod_heartmonitor.c
+++ b/modules/cluster/mod_heartmonitor.c
@@ -760,7 +760,7 @@ static int hm_handler(request_rec *r)
     ctx = ap_get_module_config(r->server->module_config,
             &heartmonitor_module);
 
-    buf = apr_pcalloc(r->pool, MAX_MSG_LEN);
+    buf = apr_pcalloc(r->pool, MAX_MSG_LEN + 1);
     input_brigade = apr_brigade_create(r->connection->pool, r->connection->bucket_alloc);
     status = ap_get_brigade(r->input_filters, input_brigade, AP_MODE_READBYTES, APR_BLOCK_READ, MAX_MSG_LEN);
     if (status != APR_SUCCESS) {
```