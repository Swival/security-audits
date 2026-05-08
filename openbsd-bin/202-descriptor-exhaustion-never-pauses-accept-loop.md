# descriptor exhaustion never pauses accept loop

## Classification

Denial of service, medium severity.

## Affected Locations

`usr.sbin/npppd/pptp/pptpd.c:621`

## Summary

The PPTP TCP accept loop intends to pause accepting when descriptor exhaustion makes `accept()` fail with `EMFILE` or `ENFILE`. The error guard is logically wrong: it requires `errno == EINTR`, making the nested `EMFILE` / `ENFILE` branch unreachable. A reachable PPTP listener can therefore remain armed and repeatedly spin on failing accepts under descriptor exhaustion.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- PPTP TCP listener is reachable by remote clients.
- The npppd process descriptor limit can be exhausted.
- Remote clients can hold enough PPTP TCP sessions to consume descriptors before later `accept()` calls.

## Proof

In `pptpd_io_event()`, failed accepts are handled as:

```c
if (errno != EAGAIN && errno == EINTR &&
    errno != ECONNABORTED) {
	if (errno == EMFILE || errno == ENFILE)
		accept_pause();
	...
}
```

This condition can only be true when `errno == EINTR`, while also excluding `EAGAIN` and `ECONNABORTED`.

As a result:

- `errno == EMFILE` cannot enter the block.
- `errno == ENFILE` cannot enter the block.
- `accept_pause()` is unreachable for descriptor exhaustion.
- The listener remains registered for read events.
- Pending TCP connections keep the listening socket readable.
- The event loop repeatedly re-enters `pptpd_io_event()` and immediately fails `accept()`.

The reproducer confirmed that enough held control sockets can make later `accept(listener->sock, ...)` fail with `EMFILE` or `ENFILE`, and that `accept_pause()` is not called.

## Why This Is A Real Bug

The surrounding code explicitly tries to back off on descriptor exhaustion:

```c
if (errno == EMFILE || errno == ENFILE)
	accept_pause();
```

That intended mitigation is dead code because the enclosing predicate excludes all errors except `EINTR`.

The accept wrapper re-arms the read event before invoking the PPTP callback, while `accept_pause()` would otherwise unarm listeners and use a one-second timer. Without the pause, descriptor exhaustion plus pending connection backlog can cause an attacker-triggered CPU/event-loop denial of service, in addition to refusing new connections.

## Fix Requirement

Change the failed-accept guard so it ignores only expected transient/non-fatal accept errors:

- `EAGAIN`
- `EINTR`
- `ECONNABORTED`

All other accept errors, including `EMFILE` and `ENFILE`, must enter the handling block so descriptor exhaustion can call `accept_pause()`.

## Patch Rationale

The patch changes the incorrect `errno == EINTR` check to `errno != EINTR`.

Before:

```c
if (errno != EAGAIN && errno == EINTR &&
    errno != ECONNABORTED) {
```

After:

```c
if (errno != EAGAIN && errno != EINTR &&
    errno != ECONNABORTED) {
```

This preserves the intended skip behavior for `EAGAIN`, `EINTR`, and `ECONNABORTED`, while allowing `EMFILE` and `ENFILE` to reach `accept_pause()`.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/npppd/pptp/pptpd.c b/usr.sbin/npppd/pptp/pptpd.c
index e6e1a9d..ee16342 100644
--- a/usr.sbin/npppd/pptp/pptpd.c
+++ b/usr.sbin/npppd/pptp/pptpd.c
@@ -619,7 +619,7 @@ pptpd_io_event(int fd, short evmask, void *ctx)
 			peerlen = sizeof(peer);
 			if ((newsock = accept(listener->sock,
 			    (struct sockaddr *)&peer, &peerlen)) < 0) {
-				if (errno != EAGAIN && errno == EINTR &&
+				if (errno != EAGAIN && errno != EINTR &&
 				    errno != ECONNABORTED) {
 					if (errno == EMFILE || errno == ENFILE)
 						accept_pause();
```