# Zero-Length PPTP Control Packet Stalls Parser

## Classification

Denial of service, high severity, certain confidence.

## Affected Locations

`usr.sbin/npppd/pptp/pptp_ctrl.c:429`

## Summary

An unauthenticated PPTP TCP peer can send a PPTP control header whose length field is zero. The parser accepts the zero length, consumes zero bytes, and repeatedly processes the same buffered packet inside the libevent callback. On affected big-endian non-debug builds, this creates an infinite loop that prevents the daemon event loop from servicing other work.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

The server accepts a PPTP TCP connection from the attacker.

## Proof

`pptp_ctrl_io_event()` reads attacker-controlled bytes into `recv_buf`, then derives `hdrlen` from `pkt[0]` and `pkt[1]`.

Before the patch, the only parser wait condition was:

```c
if (lpkt < hdrlen)
	break;	/* read again */
```

For `hdrlen == 0`, this check passes. The subsequent call:

```c
bytebuffer_get(_this->recv_buf, NULL, hdrlen);
```

advances the buffer by zero bytes, leaving the same packet at the head of `recv_buf`.

`pptp_ctrl_input(_this, pkt, 0)` is then called. In non-debug builds, `PPTP_CTRL_ASSERT(lpkt >= sizeof(struct pptp_ctrl_header))` is compiled out, so no runtime lower-bound check stops execution. With a valid control message type and magic cookie, for example `SCCRQ`, the short packet path returns `0` without closing the connection.

On big-endian builds, the in-place `ntohs()` and `ntohl()` conversions do not alter the buffered network-order bytes. The `for (;;)` loop in `pptp_ctrl_io_event()` therefore sees the same zero-length header again and repeats indefinitely.

## Why This Is A Real Bug

The parser consumes zero bytes while treating the input as a complete packet. A parser loop must either make forward progress, wait for more input, or terminate the connection. This path does none of those things. Because it runs inside the libevent I/O callback, the daemon remains stuck in that callback and cannot return to process other events, producing attacker-triggered denial of service.

The existing assertion in `pptp_ctrl_input()` is not a production defense because it is disabled unless `PPTP_CTRL_DEBUG` is defined, and the normal `usr.sbin/npppd/npppd/Makefile` does not define it.

## Fix Requirement

Reject any PPTP control packet length smaller than `sizeof(struct pptp_ctrl_header)` before consuming input from `recv_buf`.

## Patch Rationale

The patch adds a runtime lower-bound check immediately after decoding `hdrlen` and before `bytebuffer_get()` is called. Invalid packets with impossible control-header lengths now terminate the control connection through `pptp_ctrl_fini(_this)` and exit the event handler. This guarantees the parser cannot accept a zero-length packet and cannot loop without consuming input.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/npppd/pptp/pptp_ctrl.c b/usr.sbin/npppd/pptp/pptp_ctrl.c
index 7bf1ab7..5473c59 100644
--- a/usr.sbin/npppd/pptp/pptp_ctrl.c
+++ b/usr.sbin/npppd/pptp/pptp_ctrl.c
@@ -430,6 +430,10 @@ pptp_ctrl_io_event(int fd, short evmask, void *ctx)
 				break;	/* read again */
 
 			hdrlen = pkt[0] << 8 | pkt[1];
+			if (hdrlen < sizeof(struct pptp_ctrl_header)) {
+				pptp_ctrl_fini(_this);
+				goto fail;
+			}
 			if (lpkt < hdrlen)
 				break;	/* read again */
```
