# Unauthenticated TFTP Requests Create Unbounded Proxy State

## Classification

Denial of service, medium severity, confidence certain.

## Affected Locations

- `usr.sbin/tftp-proxy/tftp-proxy.c:752`
- `usr.sbin/tftp-proxy/tftp-proxy.c:439`
- `usr.sbin/tftp-proxy/tftp-proxy.c:443`
- `usr.sbin/tftp-proxy/tftp-proxy.c:476`
- `usr.sbin/tftp-proxy/tftp-proxy.c:852`
- `usr.sbin/tftp-proxy/tftp-proxy.c:859`
- `usr.sbin/tftp-proxy/tftp-proxy.c:882`
- `usr.sbin/tftp-proxy/tftp-proxy.c:893`
- `usr.sbin/tftp-proxy/tftp-proxy.c:896`
- `usr.sbin/tftp-proxy/tftp-proxy.c:905`

## Summary

`tftp-proxy` accepted every unauthenticated RRQ or WRQ datagram of at least five bytes and created persistent proxy state for each request without any global or per-source bound. A remote attacker able to reach the UDP listener could flood valid-looking TFTP requests and exhaust daemon memory, file descriptors, queued buffers, and pf rule resources.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- The `tftp-proxy` UDP listener is reachable by the attacker.
- The attacker can send RRQ or WRQ datagrams with length at least five bytes.

## Proof

`proxy_recv()` allocated a `struct proxy_request` for each received datagram before applying only minimal packet validation. Packets with length at least five bytes and opcode `RRQ` or `WRQ` were inserted into `child->fdrequests` and appended to `child->buf` for privileged processing.

The privileged process then created sockets and queued file descriptor replies for each request. Queued replies retained those descriptors until sent.

The unprivileged process consumed each reply and created pf state using `prepare_commit()`, `add_filter()` or `add_rdr()`, and `do_commit()`. After rules were committed, each request remained on `child->tmrequests` until the `transwait` timer expired and `unprivproc_timeout()` cleaned it up.

No committed global or per-source limit constrained accepted requests, pending fd requests, timed requests, privileged reply fds, evbuffer growth, or pf rule creation. A flood of valid-looking unauthenticated datagrams therefore caused unbounded resource consumption.

## Why This Is A Real Bug

The vulnerable path is reachable before authentication or any peer trust decision. Each accepted datagram can cause heap allocation, queue growth, privileged socket creation, descriptor passing, pf rule commits, and delayed cleanup. Because cleanup is timer-based and acceptance was unbounded, an attacker can send requests faster than `transwait` expiration and force resource growth until service degradation or failure.

## Fix Requirement

Add a hard request bound before allocation and before pf rule creation so unauthenticated traffic cannot create unbounded proxy state. The bound must cover both pending fd requests and timed requests because both represent live request state retained by the proxy.

## Patch Rationale

The patch introduces `MAX_REQUESTS` and a `child->nrequests` counter. `proxy_recv()` now drops and drains an incoming datagram when the global live-request count reaches the cap, preventing further allocation, evbuffer growth, fd-passing work, and pf rule creation. The counter is incremented only after a request is accepted into `child->fdrequests` and decremented when the timed request is removed in `unprivproc_timeout()`.

This bounds total live proxy state across pending and timed requests to 256 entries.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/tftp-proxy/tftp-proxy.c b/usr.sbin/tftp-proxy/tftp-proxy.c
index 1d494bb..b55710f 100644
--- a/usr.sbin/tftp-proxy/tftp-proxy.c
+++ b/usr.sbin/tftp-proxy/tftp-proxy.c
@@ -58,6 +58,7 @@
 #define DEFTRANSWAIT	2
 #define NTOP_BUFS	4
 #define PKTSIZE		SEGSIZE+4
+#define MAX_REQUESTS	256
 
 const char *opcode(int);
 const char *sock_ntop(struct sockaddr *);
@@ -192,6 +193,7 @@ struct proxy_child {
 	struct event push_ev;
 	struct event pop_ev;
 	struct evbuffer *buf;
+	size_t nrequests;
 };
 
 struct proxy_child *child = NULL;
@@ -691,6 +693,11 @@ proxy_recv(int fd, short events, void *arg)
 	struct proxy_request *r;
 	struct tftphdr *tp;
 
+	if (child->nrequests >= MAX_REQUESTS) {
+		recv(fd, safety, sizeof(safety), 0);
+		return;
+	}
+
 	r = calloc(1, sizeof(*r));
 	if (r == NULL) {
 		recv(fd, safety, sizeof(safety), 0);
@@ -756,6 +763,7 @@ proxy_recv(int fd, short events, void *arg)
 	}
 
 	TAILQ_INSERT_TAIL(&child->fdrequests, r, entry);
+	child->nrequests++;
 	evbuffer_add(child->buf, &r->addrs, sizeof(r->addrs));
 	event_add(&child->push_ev, NULL);
 
@@ -903,6 +911,7 @@ unprivproc_timeout(int fd, short events, void *arg)
 	struct proxy_request *r = arg;
 
 	TAILQ_REMOVE(&child->tmrequests, r, entry);
+	child->nrequests--;
 
 	/* delete our rdr rule and clean up */
 	prepare_commit(r->id);
```