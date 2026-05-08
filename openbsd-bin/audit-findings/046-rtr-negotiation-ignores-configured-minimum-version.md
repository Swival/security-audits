# RTR negotiation ignores configured minimum version

## Classification

Policy bypass, medium severity. Confidence: certain.

## Affected Locations

`usr.sbin/bgpd/rtr_proto.c:489`

## Summary

During RTR version negotiation, `CACHE_RESPONSE` and `CACHE_RESET` PDUs can implicitly downgrade `rs->version` below the configured `rs->min_version`. The negotiation path then marks the session established, bypassing the configured minimum-version policy.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

## Preconditions

RTR session is configured with `min_version` above the version advertised by a malicious or compromised configured RTR cache server.

## Proof

In `rtr_parse_header()`, while `rs->state == RTR_STATE_NEGOTIATION`, the `CACHE_RESPONSE` and `CACHE_RESET` cases downgrade the session when `rh.version < rs->version`:

```c
if (rh.version < rs->version) {
	rs->prev_version = rs->version;
	rs->version = rh.version;
}
rtr_fsm(rs, RTR_EVNT_NEGOTIATION_DONE);
```

This path does not check `rh.version >= rs->min_version`.

`RTR_EVNT_NEGOTIATION_DONE` then sets the session state to `RTR_STATE_ESTABLISHED`. `rtr_parse_cache_response()` accepts the same PDU in the established state and transitions to exchange via `RTR_EVNT_CACHE_RESPONSE`.

The only explicit minimum-version failure path is `RTR_EVNT_UNSUPP_PROTO_VERSION`, where negotiation fails if `rs->version < rs->min_version`; that path is not reached for a lower-version `CACHE_RESPONSE` or `CACHE_RESET`.

As a result, after downgrade, subsequent non-error PDUs are checked against the attacker-selected lower `rs->version`. Version-gated ASPA PDUs require `rs->version >= 2`, and `bgpd.conf.5` documents `min-version 2` as required to ensure ASPA synchronization.

## Why This Is A Real Bug

`min_version` is a configured security and compatibility policy. Accepting a negotiated version below that value directly contradicts the configuration and can disable version-gated RTR functionality such as ASPA synchronization. The affected code establishes the session after the downgrade, so the bypass is reachable during normal RTR negotiation with a malicious configured cache server.

## Fix Requirement

Reject negotiation downgrades where the peer PDU version is below `rs->min_version`.

## Patch Rationale

The patch adds an explicit `rh.version < rs->min_version` check before accepting `CACHE_RESPONSE` or `CACHE_RESET` during negotiation. Reusing the existing `badversion` path sends an unexpected protocol version error and prevents the state transition to `RTR_STATE_ESTABLISHED`.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/bgpd/rtr_proto.c b/usr.sbin/bgpd/rtr_proto.c
index dc4c41b..04449b3 100644
--- a/usr.sbin/bgpd/rtr_proto.c
+++ b/usr.sbin/bgpd/rtr_proto.c
@@ -482,6 +482,8 @@ rtr_parse_header(struct rtr_session *rs, struct ibuf *msg,
 		switch (rh.type) {
 		case CACHE_RESPONSE:
 		case CACHE_RESET:
+			if (rh.version < rs->min_version)
+				goto badversion;
 			/* implicit downgrade */
 			if (rh.version < rs->version) {
 				rs->prev_version = rs->version;
```