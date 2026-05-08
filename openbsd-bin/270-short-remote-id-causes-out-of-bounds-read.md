# Short Remote ID Causes Out-Of-Bounds Read

## Classification

High severity out-of-bounds read reachable from a remote IKE peer.

Confidence: certain.

## Affected Locations

`sbin/isakmpd/ike_phase_1.c:1011`

## Summary

When `Remote-ID` is configured, `ike_phase_1_recv_ID` compares the configured remote identity against attacker-controlled ID payload bytes using `memcmp`. The comparison length is derived from local policy, but the received ID payload length is not checked first. A remote peer can send a shorter ID payload and cause `memcmp` to read past the received payload buffer.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced from source-level reachability and data-flow evidence.

## Preconditions

- A phase 1 exchange reaches `ike_phase_1_recv_ID`.
- `Remote-ID` is configured for the exchange.
- The remote peer sends an ID payload whose total payload length is less than `ISAKMP_ID_DATA_OFF + configured Remote-ID length`.

## Proof

`ike_phase_1_recv_ID` obtains the peer-controlled ID payload with:

```c
payload = payload_first(msg, ISAKMP_PAYLOAD_ID);
```

When `Remote-ID` is configured, the expected identity length is computed from local policy:

```c
sz = ipsec_id_size(rs, &id_type);
```

The code then builds the expected identity into `rid` and compares it against the received payload data:

```c
memcmp(rid, payload->p + ISAKMP_ID_DATA_OFF, sz)
```

Before the patch, there was no check that:

```c
GET_ISAKMP_GEN_LENGTH(payload->p) >= ISAKMP_ID_DATA_OFF + sz
```

Therefore, a crafted ID payload shorter than the configured `Remote-ID` causes `memcmp` to read past the received payload buffer.

The reproducer confirmed reachability for a remote IKE peer. In aggressive mode, the responder accepts an initiator packet requiring an ID payload and calls `ike_phase_1_recv_ID` before authentication. `message_alloc` copies the UDP packet into an exact-size heap allocation, so the unchecked comparison can read beyond the received packet allocation.

## Why This Is A Real Bug

The read length comes from trusted local configuration, while the source buffer length is controlled by the remote peer. The validator path does not reject the short payload before `ike_phase_1_recv_ID`: `message.c` passes the received data length to `ipsec_validate_id_information`, but that function does not check the configured expected length before returning success.

This is not a theoretical bounds issue. A malicious peer can send a syntactically valid phase-1 packet with acceptable preceding payloads and a final ID payload of only `ISAKMP_ID_SZ`, causing the authentication path to perform an out-of-bounds read. The impact can be daemon termination and denial of service.

## Fix Requirement

Before comparing the received ID data against the configured `Remote-ID`, validate that the received payload length covers the ID data offset plus the expected configured identity length. Reject short payloads without calling `memcmp`.

## Patch Rationale

The patch adds a length guard immediately before the vulnerable `memcmp`:

```c
if (GET_ISAKMP_GEN_LENGTH(payload->p) <
    ISAKMP_ID_DATA_OFF + sz) {
        free(rid);
        log_print("ike_phase_1_recv_ID: "
            "received remote ID shorter than expected %s", p);
        return -1;
}
```

This preserves the existing behavior for valid and mismatching IDs while preventing `memcmp` from reading beyond the received payload. The check is placed at the point where both required values are available: the received payload length and the configured expected Remote-ID length.

## Residual Risk

None

## Patch

```diff
diff --git a/sbin/isakmpd/ike_phase_1.c b/sbin/isakmpd/ike_phase_1.c
index d0638c4..699e6ac 100644
--- a/sbin/isakmpd/ike_phase_1.c
+++ b/sbin/isakmpd/ike_phase_1.c
@@ -1070,6 +1070,13 @@ ike_phase_1_recv_ID(struct message *msg)
 		}
 
 		/* Compare expected/desired and received remote ID */
+		if (GET_ISAKMP_GEN_LENGTH(payload->p) <
+		    ISAKMP_ID_DATA_OFF + sz) {
+			free(rid);
+			log_print("ike_phase_1_recv_ID: "
+			    "received remote ID shorter than expected %s", p);
+			return -1;
+		}
 		if (memcmp(rid, payload->p + ISAKMP_ID_DATA_OFF, sz) != 0) {
 			free(rid);
 			log_print("ike_phase_1_recv_ID: "
```