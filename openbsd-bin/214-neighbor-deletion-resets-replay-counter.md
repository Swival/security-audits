# Neighbor Deletion Resets Replay Counter

## Classification

Cryptographic flaw, high severity, certain confidence.

## Affected Locations

`usr.sbin/ospfd/neighbor.c:610`

## Summary

`nbr_act_delete()` resets `nbr->crypt_seq_num` to `0` when a neighbor is deleted but retained for delayed removal. This violates OSPF cryptographic authentication replay protection because old authenticated packets with sequence numbers below the previously observed counter become acceptable again during the retained-neighbor window.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- OSPF cryptographic authentication is enabled.
- Replay protection depends on `nbr->crypt_seq_num`.
- An authenticated or malicious OSPF neighbor on the same link can observe valid authenticated packets.
- The attacker can trigger neighbor deletion, for example by allowing inactivity expiry or causing `KILL_NBR` / `LL_DOWN`.

## Proof

`nbr_fsm()` maps `NBR_EVT_ITIMER`, `NBR_EVT_KILL_NBR`, and `NBR_EVT_LL_DOWN` to `NBR_ACT_DEL`, which calls `nbr_act_delete()`.

In `nbr_act_delete()`, the neighbor is not immediately freed. The inactivity timer is stopped, then the neighbor is scheduled for removal after `DEFAULT_NBR_TMOUT`. Before the patch, the same function also executed:

```c
/* XXX reset crypt_seq_num will allow replay attacks. */
nbr->crypt_seq_num = 0;
```

Cryptographic authentication checks reject only packets whose sequence number is below the stored neighbor counter. After the reset to `0`, a previously captured authenticated packet with any nonzero sequence number can pass replay validation and update the stored counter again.

The reproduced path confirms the replayed packet is not merely authentication-accepted: after authentication succeeds, packet handling reaches `recv_hello()`, and stale Hello data can drive the neighbor FSM out of `DOWN` / `INIT`.

## Why This Is A Real Bug

The code explicitly acknowledges that resetting `crypt_seq_num` allows replay attacks. Because the neighbor object remains alive until the delayed removal timer fires, the replay state is reset while packets for that neighbor can still be processed.

This breaks the core replay-protection invariant: sequence numbers that were already observed and should remain stale become valid again after neighbor deletion.

## Fix Requirement

Do not reset `nbr->crypt_seq_num` while the neighbor object is retained and can still be used for packet authentication. The replay counter must either be preserved until final free or packets must be rejected until the neighbor is fully removed.

## Patch Rationale

The patch removes the unconditional reset of `nbr->crypt_seq_num` from `nbr_act_delete()`.

This preserves the highest authenticated sequence number observed for the retained neighbor, so replayed packets with older sequence numbers remain rejected during the delayed-removal window.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/ospfd/neighbor.c b/usr.sbin/ospfd/neighbor.c
index 83712fe..766ce87 100644
--- a/usr.sbin/ospfd/neighbor.c
+++ b/usr.sbin/ospfd/neighbor.c
@@ -610,9 +610,6 @@ nbr_act_delete(struct nbr *nbr)
 	/* stop timers */
 	nbr_stop_itimer(nbr);
 
-	/* XXX reset crypt_seq_num will allow replay attacks. */
-	nbr->crypt_seq_num = 0;
-
 	/* schedule kill timer */
 	timerclear(&tv);
 	tv.tv_sec = DEFAULT_NBR_TMOUT;
```