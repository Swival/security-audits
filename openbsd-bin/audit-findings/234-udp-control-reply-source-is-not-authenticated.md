# UDP control reply source is not authenticated

## Classification

Authentication bypass; medium severity; confidence certain.

## Affected Locations

`usr.bin/talk/ctl_transact.c:95`

## Summary

`ctl_transact()` sends UDP control requests to `daemon_addr`, then accepts replies using `recv()`, which does not capture or validate the sender address. The acceptance loop only checks `CTL_RESPONSE.vers` and `CTL_RESPONSE.type`. Any host that can send a UDP packet to the client control socket before the legitimate daemon can forge a response that is accepted as the target `talkd` reply.

## Provenance

Verified by reproduced source review and patch analysis.

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

An attacker can send UDP packets to the client's `ctl_sockt` before the real daemon reply arrives.

## Proof

`ctl_transact()` sets `daemon_addr.sin_addr = target` and `daemon_addr.sin_port = daemon_port`, then sends the control message to that daemon address with `sendto()`.

Before the patch, the receive path used:

```c
cc = recv(ctl_sockt, (char *)rp, sizeof (*rp), 0);
```

Because `recv()` does not return the UDP datagram source, the client cannot distinguish a legitimate daemon reply from a forged packet.

The only acceptance condition was:

```c
rp->vers == TALK_VERSION && rp->type == type
```

A forged `CTL_RESPONSE` with the expected `TALK_VERSION` and response `type` is therefore accepted regardless of source IP or source port.

This was reproduced as weaponizable during `LOOK_UP`: `look_for_invite()` accepts `answer == SUCCESS`, after which `check_local()` connects to the address supplied in the attacker-controlled response, allowing impersonation of a talk invitation or peer.

## Why This Is A Real Bug

UDP provides no built-in peer authentication for unconnected sockets. Since the client neither connects the UDP socket to the daemon nor validates the source address returned by `recvfrom()`, any reachable sender can race the legitimate daemon.

The bug is not merely theoretical because the accepted response affects later client behavior. A forged successful lookup can cause the client to trust attacker-supplied response data and connect to an attacker-controlled address.

## Fix Requirement

Receive control replies with `recvfrom()` and reject responses unless the datagram source address and source port match the expected `daemon_addr`.

## Patch Rationale

The patch records the sender address for each UDP response:

```c
fromlen = sizeof (from);
cc = recvfrom(ctl_sockt, (char *)rp, sizeof (*rp), 0,
    (struct sockaddr *)&from, &fromlen);
```

It then extends both response-acceptance loops to require:

```c
from.sin_addr.s_addr == daemon_addr.sin_addr.s_addr
from.sin_port == daemon_addr.sin_port
```

This preserves the existing retry behavior and version/type checks while binding accepted responses to the daemon address used for `sendto()`.

## Residual Risk

None

## Patch

`234-udp-control-reply-source-is-not-authenticated.patch`

```diff
diff --git a/usr.bin/talk/ctl_transact.c b/usr.bin/talk/ctl_transact.c
index 8852b06..d8789db 100644
--- a/usr.bin/talk/ctl_transact.c
+++ b/usr.bin/talk/ctl_transact.c
@@ -50,6 +50,8 @@ void
 ctl_transact(struct in_addr target, CTL_MSG msg, int type, CTL_RESPONSE *rp)
 {
 	struct pollfd pfd[1];
+	struct sockaddr_in from;
+	socklen_t fromlen;
 	int nready, cc;
 
 	msg.type = type;
@@ -86,7 +88,9 @@ ctl_transact(struct in_addr target, CTL_MSG msg, int type, CTL_RESPONSE *rp)
 		 * request/acknowledgements being sent)
 		 */
 		do {
-			cc = recv(ctl_sockt, (char *)rp, sizeof (*rp), 0);
+			fromlen = sizeof (from);
+			cc = recvfrom(ctl_sockt, (char *)rp, sizeof (*rp), 0,
+			    (struct sockaddr *)&from, &fromlen);
 			if (cc < 0) {
 				if (errno == EINTR)
 					continue;
@@ -94,7 +98,11 @@ ctl_transact(struct in_addr target, CTL_MSG msg, int type, CTL_RESPONSE *rp)
 			}
 			nready = poll(pfd, 1, 0);
 		} while (nready > 0 && (rp->vers != TALK_VERSION ||
-		    rp->type != type));
-	} while (rp->vers != TALK_VERSION || rp->type != type);
+		    rp->type != type ||
+		    from.sin_addr.s_addr != daemon_addr.sin_addr.s_addr ||
+		    from.sin_port != daemon_addr.sin_port));
+	} while (rp->vers != TALK_VERSION || rp->type != type ||
+	    from.sin_addr.s_addr != daemon_addr.sin_addr.s_addr ||
+	    from.sin_port != daemon_addr.sin_port);
 	rp->id_num = ntohl(rp->id_num);
 }
```