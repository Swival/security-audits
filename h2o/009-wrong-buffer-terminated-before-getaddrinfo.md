# Wrong service buffer left unterminated before `getaddrinfo`

## Classification
- Type: invariant violation
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/handler/mruby/middleware.c:286`

## Summary
`parse_hostport` allocates separate `hostname` and `servname` buffers on the non-IPv4 slow path, but writes the terminating `'\0'` to `hostname[port.len]` instead of `servname[port.len]`. As a result, `getaddrinfo(hostname, servname, ...)` is called with an unterminated service string on reachable input from Rack environment port fields.

## Provenance
- Verified from the provided reproducer and patch target in `lib/handler/mruby/middleware.c`
- Independent reproduction summary confirms observable misresolution behavior
- Scanner source: https://swival.dev

## Preconditions
- `SERVER_PORT` or `REMOTE_PORT` reaches the `parse_hostport` slow path
- Input is not handled by the IPv4 fast path
- Heap contents after the copied port bytes do not already contain an immediate zero byte

## Proof
Rack env values flow into `conn.server.port` and `conn.remote.port` in subrequest construction, then into `get_sockname` / `get_peername`, which call `parse_hostport`. On the slow path:
- `servname = h2o_mem_alloc_pool(pool, char, port.len + 1);`
- `memcpy(servname, port.base, port.len);`
- `hostname[port.len] = '\0';`

The final line terminates the wrong buffer. `servname` remains unterminated when passed to `getaddrinfo(hostname, servname, ...)`.

The reproduced PoC using the same allocation pattern and logic showed host `::1` with port `80` being interpreted as service bytes `38 30 32 32 32 32` (`"802222"`), causing `getaddrinfo` to fail with `EAI_NONAME`. The same bad write also truncates `hostname` when `port.len < host.len`.

## Why This Is A Real Bug
This is reachable from normal Rack env-derived port strings and violates `getaddrinfo`'s requirement for NUL-terminated input strings. The impact is observable: address resolution can fail or parse the wrong service/host, producing lost or incorrect local/remote address metadata for subrequests. The reproducer demonstrates actual behavioral failure, so this is not merely theoretical.

## Fix Requirement
Terminate the service buffer before calling `getaddrinfo`:
- replace the incorrect write with `servname[port.len] = '\0';`

## Patch Rationale
The bug is a single-buffer termination mistake. Writing the terminator into `servname` restores the expected string invariant for the service argument while leaving `hostname` intact. This directly addresses both observed effects: stray bytes appended to the service string and unintended hostname truncation.

## Residual Risk
None

## Patch
```diff
diff --git a/lib/handler/mruby/middleware.c b/lib/handler/mruby/middleware.c
index 0000000..0000000 100644
--- a/lib/handler/mruby/middleware.c
+++ b/lib/handler/mruby/middleware.c
@@ -286,7 +286,7 @@ static int parse_hostport(h2o_mem_pool_t *pool, h2o_iovec_t host, h2o_iovec_t po
         hostname = h2o_mem_alloc_pool(pool, char, host.len + 1);
         memcpy(hostname, host.base, host.len);
         servname = h2o_mem_alloc_pool(pool, char, port.len + 1);
         memcpy(servname, port.base, port.len);
-        hostname[port.len] = '\0';
+        servname[port.len] = '\0';
         struct addrinfo hints = {AI_NUMERICHOST | AI_NUMERICSERV, family, socktype};
         struct addrinfo *res;
         if (getaddrinfo(hostname, servname, &hints, &res) != 0)
```