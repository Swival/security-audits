# Failed PPP Bind Is Marked Established

## Classification

Denial of service, medium severity, certain confidence.

## Affected Locations

`usr.sbin/npppd/l2tp/l2tp_call.c:233`

## Summary

An L2TP ICCN path ignores failure from `l2tp_call_bind_ppp()`. When dial-in proxy is requested while `accept_dialin` is false, PPP binding fails, `_this->ppp` is cleared, and the call is disconnected. The caller then overwrites the cleanup state with `L2TP_CALL_STATE_ESTABLISHED`. A later L2TP data packet reaches `l2tp_call_ppp_input()` and dereferences the NULL PPP pointer, crashing `npppd`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- An L2TP control session exists.
- `accept_dialin` is false.
- A remote L2TP peer can send ICCN requesting dial-in proxy.
- The peer can send a follow-up L2TP data packet for the assigned session id.

## Proof

- In `l2tp_call_recv_packet()` WAIT_CONN ICCN handling, `l2tp_call_bind_ppp(_this, &dpi)` is called before ZLB, establishment, and `ncalls` increment.
- The original caller ignores the return value from `l2tp_call_bind_ppp()`.
- In `l2tp_call_bind_ppp()`, `DIALIN_PROXY_IS_REQUESTED(dpi)` with `accept_dialin` false enters the failure path.
- The failure path destroys `ppp`, sets `_this->ppp = NULL`, calls `l2tp_call_disconnect()`, and returns nonzero.
- Because the caller ignores that nonzero return, it sends ZLB, sets `_this->state = L2TP_CALL_STATE_ESTABLISHED`, and increments `_this->ctrl->ncalls`.
- A subsequent data packet passes the established control/call checks in the L2TP control path and reaches `l2tp_call_ppp_input()`.
- `l2tp_call_ppp_input()` assigns `ppp = _this->ppp` and immediately dereferences `ppp->recv_packet`, causing a NULL pointer dereference.

## Why This Is A Real Bug

The callee explicitly reports PPP bind failure and has already moved the call into cleanup by invoking `l2tp_call_disconnect()`. The caller then disregards that failure and publishes the call as established. This creates an externally reachable state where an established L2TP call has no PPP object. The later dereference in `l2tp_call_ppp_input()` is unconditional, so a remote peer can crash the daemon after triggering the failed bind condition.

## Fix Requirement

Check the return value of `l2tp_call_bind_ppp()` and do not send ZLB, mark the call established, or increment `ncalls` when PPP binding fails.

## Patch Rationale

The patch preserves the existing successful ICCN behavior while stopping state advancement after a failed bind. Returning immediately on nonzero `l2tp_call_bind_ppp()` leaves the disconnect/cleanup performed by the failure path intact and prevents an established call from existing with `_this->ppp == NULL`.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/npppd/l2tp/l2tp_call.c b/usr.sbin/npppd/l2tp/l2tp_call.c
index b20657d..8891925 100644
--- a/usr.sbin/npppd/l2tp/l2tp_call.c
+++ b/usr.sbin/npppd/l2tp/l2tp_call.c
@@ -222,7 +222,8 @@ l2tp_call_recv_packet(l2tp_ctrl *ctrl, l2tp_call *_this, int mestype,
 			memset(&dpi, 0, sizeof(dpi));
 			if (l2tp_call_recv_ICCN(_this, pkt, pktlen, &dpi) != 0)
 				return 1;
-			l2tp_call_bind_ppp(_this, &dpi);
+			if (l2tp_call_bind_ppp(_this, &dpi) != 0)
+				return 1;
 			l2tp_call_send_ZLB(_this);
 			_this->state = L2TP_CALL_STATE_ESTABLISHED;
 			_this->ctrl->ncalls++;
```