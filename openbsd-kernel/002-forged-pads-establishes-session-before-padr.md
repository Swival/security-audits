# forged PADS establishes session before PADR

## Classification

Authorization bypass, medium severity.

## Affected Locations

`net/if_pppoe.c:574`

`net/if_pppoe.c:659`

`net/if_pppoe.c:665`

## Summary

A malicious host on the PPPoE broadcast segment can forge a `PADS` packet containing an observed `HUNIQUE` while the victim is still in `PPPOE_STATE_PADI_SENT`. The discovery handler accepts the matching softc and transitions directly to `PPPOE_STATE_SESSION` without first requiring that the victim sent `PADR`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The victim PPPoE interface is in discovery.
- The victim has sent `PADI` and is in `PPPOE_STATE_PADI_SENT`.
- The victim's `HUNIQUE` value is observable by an attacker on the PPPoE broadcast segment.
- The attacker can inject PPPoE discovery frames on that segment.

## Proof

`pppoe_dispatch_disc_pkt` parses discovery tags and resolves `PPPOE_TAG_HUNIQUE` through `pppoe_find_softc_by_hunique`.

`pppoe_find_softc_by_hunique` accepts a matching softc when:

```c
sc->sc_state >= PPPOE_STATE_PADI_SENT && sc->sc_state < PPPOE_STATE_SESSION
```

This includes `PPPOE_STATE_PADI_SENT`.

In the `PPPOE_CODE_PADO` case, the code correctly requires:

```c
sc->sc_state == PPPOE_STATE_PADI_SENT
```

and then sends `PADR`, moving the state to `PPPOE_STATE_PADR_SENT`.

In the vulnerable `PPPOE_CODE_PADS` case, the code only checks:

```c
if (sc == NULL)
	goto done;
```

It then accepts the packet, stores the attacker-controlled session id, cancels the discovery timeout, changes state to `PPPOE_STATE_SESSION`, inserts the softc into `pppoe_sessions`, and calls `pp_up`.

Therefore, a forged `PADS` carrying the observed `HUNIQUE` during `PADI_SENT` reaches session establishment without a prior `PADR`.

## Why This Is A Real Bug

PPPoE discovery has an ordered handshake: `PADI -> PADO -> PADR -> PADS`. A `PADS` is only valid as confirmation of a prior `PADR`.

The implementation enforces the expected state for `PADO`, but not for `PADS`. Because `HUNIQUE` lookup intentionally matches any discovery state from `PADI_SENT` up to, but not including, `SESSION`, the missing `PADS` state check allows an attacker to skip the `PADO/PADR` portion of the handshake.

The reproduced path shows the victim enters `SESSION` with an attacker-chosen session id. Even though `sc_dest` is not updated from the forged `PADS` source MAC when skipping `PADO`, inbound PPPoE data lookup is keyed by session/interface rather than peer MAC, so the unauthorized session state remains meaningful.

## Fix Requirement

In `PPPOE_CODE_PADS` handling, accept `PADS` only when the softc is in `PPPOE_STATE_PADR_SENT`.

## Patch Rationale

The patch adds the missing state validation immediately after confirming that `sc` was found. This preserves valid discovery behavior while rejecting out-of-order `PADS` packets that arrive before a `PADR` has been sent.

The check mirrors the protocol state machine: only `PADR_SENT` may transition to `SESSION` on receipt of `PADS`.

## Residual Risk

None

## Patch

```diff
diff --git a/net/if_pppoe.c b/net/if_pppoe.c
index a5208d2..50893b3 100644
--- a/net/if_pppoe.c
+++ b/net/if_pppoe.c
@@ -659,6 +659,8 @@ breakbreak:
 	case PPPOE_CODE_PADS:
 		if (sc == NULL)
 			goto done;
+		if (sc->sc_state != PPPOE_STATE_PADR_SENT)
+			goto done;
 
 		KERNEL_ASSERT_LOCKED();
```