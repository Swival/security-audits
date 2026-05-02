# accepted RPC connection null-dereferences failed transporter allocation

## Classification

Denial of service, medium severity.

## Affected Locations

`rpc/svc_tcp.c:286`

## Summary

`rendezvous_request()` accepts an unauthenticated remote TCP connection and passes the accepted socket to `makefd_xprt()`. If transporter allocation or registration fails, `makefd_xprt()` returns `NULL`, but `rendezvous_request()` immediately writes through the returned pointer. This crashes the RPC service process with a NULL pointer dereference.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The server uses `svctcp_create()`.
- Memory allocation can fail, or `__xprt_register()` can fail.
- An unauthenticated remote TCP client can connect to the RPC TCP listener.

## Proof

`svctcp_create()` installs `svctcp_rendezvous_op` as the listener transport operation table. Its receive callback is `rendezvous_request()`.

When the listener fd is readable, the RPC service loop calls `SVC_RECV(xprt, &msg)`, so an unauthenticated TCP connection reaches `rendezvous_request()`.

In `rendezvous_request()`:

- `accept()` accepts the remote connection.
- The accepted socket is passed to `makefd_xprt(sock, r->sendsize, r->recvsize)`.
- `makefd_xprt()` can return `NULL` when `mem_alloc(sizeof(SVCXPRT))` fails.
- `makefd_xprt()` can return `NULL` when `mem_alloc(sizeof(struct tcp_conn))` fails.
- `makefd_xprt()` can return `NULL` when `__xprt_register(xprt)` fails.
- `rendezvous_request()` then immediately executes `xprt->xp_raddr = addr` and `xprt->xp_addrlen = len`.

Therefore, an attacker-triggered accepted TCP connection can reach a failed `makefd_xprt()` path and cause a NULL pointer dereference in the RPC service process.

## Why This Is A Real Bug

The failure return from `makefd_xprt()` is explicitly possible and already part of the function contract used by `svcfd_create()`. `rendezvous_request()` does not check that return value before dereferencing it.

The trigger is remote and unauthenticated: opening a TCP connection to a service using `svctcp_create()` is enough to reach the vulnerable allocation path. If allocation or registration fails at that point, the process dereferences `NULL` and terminates, producing denial of service.

## Fix Requirement

Check the result of `makefd_xprt()` before dereferencing it. If transporter creation fails, close the accepted socket and return without touching the NULL pointer.

## Patch Rationale

The patch adds a NULL check immediately after `makefd_xprt()` in `rendezvous_request()`.

If transporter creation fails:

- the accepted socket is closed to avoid a file descriptor leak;
- the function returns `FALSE`, matching the existing rendezvous behavior that no RPC message is processed;
- `xprt->xp_raddr` and `xprt->xp_addrlen` are only written after a valid transporter exists.

This preserves normal successful behavior while making the allocation and registration failure paths safe.

## Residual Risk

None

## Patch

```diff
diff --git a/rpc/svc_tcp.c b/rpc/svc_tcp.c
index 6339f9a..38ee698 100644
--- a/rpc/svc_tcp.c
+++ b/rpc/svc_tcp.c
@@ -286,6 +286,10 @@ rendezvous_request(SVCXPRT *xprt, struct rpc_msg *ignored)
 	 * make a new transporter (re-uses xprt)
 	 */
 	xprt = makefd_xprt(sock, r->sendsize, r->recvsize);
+	if (xprt == NULL) {
+		close(sock);
+		return (FALSE);
+	}
 	xprt->xp_raddr = addr;
 	xprt->xp_addrlen = len;
 	return (FALSE); /* there is never an rpc msg to be processed */
```