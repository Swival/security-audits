# Zero-Length LSA Causes Unbounded Update Parsing

## Classification

Denial of service, high severity.

Confidence: certain.

## Affected Locations

`usr.sbin/ospfd/lsupdate.c:262`

## Summary

`recv_ls_update()` accepts LS Update packets from neighbors in `XCHNG`, `LOAD`, or `FULL` state and iterates over the packet-controlled `nlsa` count. The parser validates that the remaining packet length is not smaller than `lsa.len`, but it does not reject an LSA length smaller than the fixed LSA header.

A malicious accepted OSPF neighbor can set the first LSA header length to zero. That zero length passes the existing bounds check, causes a zero-length RDE IPC message to be queued, and does not advance `buf` or reduce `len`. A large attacker-controlled `nlsa` value then drives repeated parsing and IPC work from one tiny packet.

## Provenance

Found by Swival Security Scanner: https://swival.dev

The finding was manually reproduced and patched.

## Preconditions

- The attacker is an accepted OSPF neighbor.
- The neighbor state is `XCHNG`, `LOAD`, or `FULL`.
- The attacker can send an LS Update with a large `nlsa` and an LSA header whose `lsa.len` field is zero.

## Proof

In `recv_ls_update()`, packets in `XCHNG`, `LOAD`, or `FULL` enter:

```c
for (; nlsa > 0 && len > 0; nlsa--) {
```

The loop first verifies that enough bytes remain for an LSA header, then copies that header:

```c
if (len < sizeof(lsa)) {
	...
	return;
}
memcpy(&lsa, buf, sizeof(lsa));
```

The vulnerable check only rejects LSAs whose declared length exceeds the remaining packet length:

```c
if (len < ntohs(lsa.len)) {
	...
	return;
}
```

For `lsa.len == 0`, the check succeeds because `len < 0` is false. The code then sends a zero-length payload to the RDE and advances by zero bytes:

```c
ospfe_imsg_compose_rde(IMSG_LS_UPD, nbr->peerid, 0,
    buf, ntohs(lsa.len));
buf += ntohs(lsa.len);
len -= ntohs(lsa.len);
```

Because `buf` and `len` do not change, the loop repeats until the packet-controlled `nlsa` count reaches zero. Zero-length imsg payloads are accepted by the imsg layer, so the frontend performs repeated CPU work and queues many IPC messages before downstream validation can reject the malformed LSA.

## Why This Is A Real Bug

The parser fails to enforce the OSPF invariant that each LSA must be at least `sizeof(struct lsa_hdr)` bytes long.

This is exploitable by an already accepted OSPF neighbor in valid flooding states. The attacker does not need to send a large packet; a small LS Update with a valid-sized LSA header, `lsa.len == 0`, and a large `nlsa` value is sufficient to force up to an attacker-chosen 32-bit iteration count and repeated RDE IPC queueing from a single packet.

RDE-side LSA validation does not prevent the denial of service because the expensive frontend loop and IPC enqueueing happen before RDE rejection.

## Fix Requirement

Reject any LSA whose declared length is smaller than the fixed LSA header before composing the RDE IPC message or advancing the packet cursor.

## Patch Rationale

The patch adds the missing lower-bound check to the existing packet-size validation:

```c
if (ntohs(lsa.len) < sizeof(lsa) || len < ntohs(lsa.len)) {
```

This preserves the existing upper-bound check while enforcing forward progress through the LS Update payload. Any accepted LSA must now consume at least one complete `struct lsa_hdr`, so `buf` advances and `len` decreases on every successful iteration.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/ospfd/lsupdate.c b/usr.sbin/ospfd/lsupdate.c
index 7a9872a..e34288f 100644
--- a/usr.sbin/ospfd/lsupdate.c
+++ b/usr.sbin/ospfd/lsupdate.c
@@ -269,7 +269,7 @@ recv_ls_update(struct nbr *nbr, char *buf, u_int16_t len)
 				return;
 			}
 			memcpy(&lsa, buf, sizeof(lsa));
-			if (len < ntohs(lsa.len)) {
+			if (ntohs(lsa.len) < sizeof(lsa) || len < ntohs(lsa.len)) {
 				log_warnx("recv_ls_update: bad packet size, "
 				    "neighbor ID %s (%s)", inet_ntoa(nbr->id),
 				    nbr->iface->name);
```