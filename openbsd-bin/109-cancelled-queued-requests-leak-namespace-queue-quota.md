# Cancelled queued requests leak namespace queue quota

## Classification

Denial of service, medium severity. Confidence: certain.

## Affected Locations

`usr.sbin/ldapd/namespace.c:536`

## Summary

When a namespace is reopening, modification requests are queued and counted in `ns->queued_requests`. If a client disconnects before replay, `namespace_cancel_conn()` removes and frees that client’s queued requests but does not decrement the counter. Repeating this leaves `ns->queued_requests` inflated while the actual queue is empty, causing later queued modification requests to fail with `LDAP_BUSY`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- The namespace is reopening.
- Modification requests are accepted into `ns->request_queue`.
- A remote LDAP client disconnects after its requests are queued and before replay.

## Proof

`namespace_queue_request()` inserts each request into `ns->request_queue` and increments `ns->queued_requests`.

`namespace_cancel_conn()` iterates all namespaces, removes queued requests belonging to the disconnecting connection, and calls `request_free(req)`, but previously did not decrement `ns->queued_requests`.

`namespace_queue_replay()` decrements only after replaying an actual queue entry. If disconnect cancellation has already emptied the queue, replay returns early and the inflated counter persists.

A remote client can queue 10001 requests during namespace reopen, then disconnect. The request queue becomes empty, but `ns->queued_requests` remains 10001. Later calls to `namespace_queue_request()` hit the quota check:

```c
if (ns->queued_requests > MAX_REQUEST_QUEUE)
	return -1;
```

Callers then report `LDAP_BUSY` despite no real queued load.

## Why This Is A Real Bug

The counter is intended to mirror the number of queued requests. One removal path, `namespace_queue_replay()`, decrements it, but the disconnect cancellation path did not. This violates the queue accounting invariant and lets an unauthenticated or authenticated remote LDAP client with an established connection poison namespace queue quota during reopen windows.

The impact is denial of service for operations that require namespace queueing during the same or later reopen periods. The poisoned quota persists until the namespace is destroyed or the daemon restarts.

## Fix Requirement

Whenever `namespace_cancel_conn()` removes a request from `ns->request_queue`, it must also decrement `ns->queued_requests`.

## Patch Rationale

The patch updates the cancellation path to maintain the same accounting invariant as the replay path. Each successful `TAILQ_REMOVE()` for a queued request is paired with `ns->queued_requests--` before freeing the request.

This makes the quota reflect the actual queue length after client disconnects and prevents stale counter inflation from causing false `LDAP_BUSY` responses.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/ldapd/namespace.c b/usr.sbin/ldapd/namespace.c
index db3bb3e..d2c828c 100644
--- a/usr.sbin/ldapd/namespace.c
+++ b/usr.sbin/ldapd/namespace.c
@@ -536,6 +536,7 @@ namespace_cancel_conn(struct conn *conn)
 
 			if (req->conn == conn) {
 				TAILQ_REMOVE(&ns->request_queue, req, next);
+				ns->queued_requests--;
 				request_free(req);
 			}
 		}
```