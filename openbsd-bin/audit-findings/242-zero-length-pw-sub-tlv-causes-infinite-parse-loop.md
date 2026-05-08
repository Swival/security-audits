# Zero-Length PW Sub-TLV Causes Infinite Parse Loop

## Classification

Denial of service, high severity, certain confidence.

## Affected Locations

`usr.sbin/ldpd/labelmapping.c:833`

## Summary

A malicious established LDP peer can send a PWID FEC containing an unknown interface parameter sub-TLV with length zero. The PWID parser accepts the zero length, ignores the unknown sub-TLV, and then advances by zero bytes, causing `while (pw_len > 0)` to spin forever on attacker-controlled input.

## Provenance

Found by Swival Security Scanner: https://swival.dev

## Preconditions

- An LDP session is established.
- The daemon accepts peer Label Mapping, Request, Withdraw, Release, or Abort messages.
- The peer can send a PWID FEC with optional interface parameter sub-TLV data.

## Proof

Peer-controlled label messages reach the vulnerable parser:

- `usr.sbin/ldpd/packet.c:555` routes peer Label Mapping/Request/Withdraw/Release/Abort messages to `recv_labelmessage` once `nbr->state == NBR_STA_OPER`.
- `usr.sbin/ldpd/labelmapping.c:167` passes the FEC TLV body directly into `tlv_decode_fec_elm`.
- For `MAP_TYPE_PWID`, `usr.sbin/ldpd/labelmapping.c:776` accepts `len == FEC_PWID_ELM_MIN_LEN + pw_len`.
- A valid malicious body can set `pw_len = 6`, containing a 4-byte PW ID followed by a 2-byte sub-TLV header.
- At `usr.sbin/ldpd/labelmapping.c:813`, an unknown sub-TLV with `{ type = unknown, length = 0 }` passes the existing `stlv.length > pw_len` check.
- The `default` branch at `usr.sbin/ldpd/labelmapping.c:832` ignores the unknown sub-TLV.
- `off += stlv.length` and `pw_len -= stlv.length` at `usr.sbin/ldpd/labelmapping.c:836` make no progress because `stlv.length == 0`.
- The loop condition `while (pw_len > 0)` remains true forever.

## Why This Is A Real Bug

The parser operates synchronously while processing a received peer message. With `pw_len > 0` and `stlv.length == 0`, neither the input offset nor the remaining length changes. The function never returns to the packet loop, producing a concrete peer-triggered CPU denial of service.

## Fix Requirement

Reject zero-length PW interface parameter sub-TLVs before dispatching on the sub-TLV type, or otherwise require each loop iteration to consume at least one byte.

## Patch Rationale

The patch changes the existing bounds check from:

```c
if (stlv.length > pw_len) {
```

to:

```c
if (stlv.length == 0 || stlv.length > pw_len) {
```

This preserves the existing malformed-length handling path while adding a progress guarantee. Any accepted sub-TLV now has a positive length not exceeding the remaining `pw_len`, so `off += stlv.length` and `pw_len -= stlv.length` always move the parser toward termination.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/ldpd/labelmapping.c b/usr.sbin/ldpd/labelmapping.c
index 730f61f..0558aab 100644
--- a/usr.sbin/ldpd/labelmapping.c
+++ b/usr.sbin/ldpd/labelmapping.c
@@ -811,7 +811,7 @@ tlv_decode_fec_elm(struct nbr *nbr, struct ldp_msg *msg, char *buf,
 			}
 
 			memcpy(&stlv, buf + off, sizeof(stlv));
-			if (stlv.length > pw_len) {
+			if (stlv.length == 0 || stlv.length > pw_len) {
 				session_shutdown(nbr, S_BAD_TLV_LEN, msg->id,
 				    msg->type);
 				return (-1);
```