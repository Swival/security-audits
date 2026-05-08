# DNS Response Validation Skips Responder Address on Session Socket

## Classification

Injection, medium severity. Confidence: certain.

## Affected Locations

`usr.sbin/relayd/relay_udp.c:440`

## Summary

`relayd` DNS-over-UDP response validation checked the randomized DNS transaction ID on the per-session UDP socket, but did not verify that the datagram source address matched the upstream responder recorded in `con->se_out.ss`. An attacker able to send UDP packets to the relay's per-session source port and guess the 16-bit randomized DNS ID could inject a forged DNS response that `relayd` would forward to the original client.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was manually reproduced and patched from the supplied source and reproducer evidence.

## Preconditions

- The attacker can send UDP datagrams to the relay's per-session UDP source port.
- The attacker can guess or otherwise learn the randomized 16-bit DNS ID stored in `priv->dp_inkey`.
- A DNS relay session is active and awaiting a response.

## Proof

`relay_udp_response()` receives datagrams on the per-session socket and passes the source address to protocol validation:

`usr.sbin/relayd/relay_udp.c:190`

```c
priv = (*proto->validate)(con, rlay, &ss, buf, len)
```

For DNS responses with `con != NULL`, `relay_dns_validate()` previously accepted the response if the DNS ID matched `priv->dp_inkey`:

`usr.sbin/relayd/relay_udp.c:440`

```c
if (priv == NULL || key != priv->dp_inkey) {
	relay_close(con, "invalid response", 1);
	return (NULL);
}
relay_dns_result(con, buf, len);
```

This branch did not compare `ss` with `con->se_out.ss`. By contrast, the listener-path lookup for `con == NULL` already required the responder address to match:

`usr.sbin/relayd/relay_udp.c:432`

```c
relay_cmp_af(ss, &con->se_out.ss) == 0
```

Once accepted, `relay_dns_result()` rewrites the DNS ID back to the client's original `dp_outkey` and forwards the attacker-controlled payload to the original client:

`usr.sbin/relayd/relay_udp.c:528`

```c
hdr->dns_id = htons(priv->dp_outkey);
```

`usr.sbin/relayd/relay_udp.c:532`

```c
sendto(rlay->rl_s, buf, len, 0, (struct sockaddr *)&con->se_in.ss, slen)
```

Therefore, a forged UDP datagram from the wrong source address but with the correct randomized DNS ID is accepted and forwarded to the client.

## Why This Is A Real Bug

The code already encodes the intended invariant in the `con == NULL` response path: a DNS response must match both the randomized DNS ID and the expected upstream responder address. The per-session socket path enforced only the DNS ID. UDP sockets can receive datagrams from arbitrary peers unless connected or explicitly filtered, so the missing source-address check creates an injection path. The reproduced control flow shows the forged payload reaches `relay_dns_result()` and is sent to `con->se_in.ss`.

## Fix Requirement

In the `con != NULL` branch of `relay_dns_validate()`, reject DNS responses unless:

- `con->se_priv` is present.
- The response DNS ID equals `priv->dp_inkey`.
- The datagram source address matches `con->se_out.ss` via `relay_cmp_af(ss, &con->se_out.ss) == 0`.

## Patch Rationale

The patch applies the same responder-address invariant already used by the `con == NULL` path to the per-session socket path. This prevents an off-path or wrong-peer datagram with a guessed DNS ID from being accepted as the upstream response.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/relayd/relay_udp.c b/usr.sbin/relayd/relay_udp.c
index cac1059..9eda5a7 100644
--- a/usr.sbin/relayd/relay_udp.c
+++ b/usr.sbin/relayd/relay_udp.c
@@ -439,7 +439,8 @@ relay_dns_validate(struct rsession *con, struct relay *rlay,
 			relay_dns_result(con, buf, len);
 	} else {
 		priv = con->se_priv;
-		if (priv == NULL || key != priv->dp_inkey) {
+		if (priv == NULL || key != priv->dp_inkey ||
+		    relay_cmp_af(ss, &con->se_out.ss) != 0) {
 			relay_close(con, "invalid response", 1);
 			return (NULL);
 		}
```