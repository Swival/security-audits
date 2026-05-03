# Client-Controlled Response Address Enables UDP Reflection

## Classification

Denial of service, medium severity.

## Affected Locations

`talkd/talkd.c:116`

## Summary

`talkd` accepted an unauthenticated UDP request, copied the reply destination from attacker-controlled `request.ctl_addr`, and sent a `CTL_RESPONSE` to that address. A remote client could set `ctl_addr` to an arbitrary IPv4 victim and cause the daemon to emit UDP traffic to the victim, making `talkd` a UDP reflector.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

`talkd` receives attacker-controlled UDP datagrams on its standard input socket.

## Proof

The issue was reproduced.

A client sends a full-size `CTL_MSG` to `ntalkd` with `request.ctl_addr.sa_family` set to network-order `AF_INET` and the embedded IPv4 address and port set to a victim.

Observed data flow:

- `talkd/talkd.c:97` reads the attacker-controlled datagram directly into `request`.
- `talkd/talkd.c:100` only requires the datagram to be exactly `sizeof(request)`.
- `talkd/talkd.c:111` copies `request.ctl_addr` into `ctl_addr`.
- `talkd/talkd.c:112` rewrites only the family from network to host order.
- `talkd/talkd.c:113` sets `sa_len`, preserving attacker-controlled IPv4 destination bytes.
- `talkd/process.c:91` compares the packet source address with `mp->ctl_addr`, but `talkd/process.c:100` only logs when they differ and continues.
- `talkd/talkd.c:120` sends the `CTL_RESPONSE` to `ctl_addr`, not to the `recvfrom` source stored in `response.addr`.

Impact: an unauthenticated remote client can repeatedly cause the daemon to send UDP responses to an arbitrary IPv4 victim.

## Why This Is A Real Bug

The daemon already obtains the actual packet source through `recvfrom` into `response.addr`, but does not use that address for the reply. Instead, it trusts `request.ctl_addr`, which is part of the attacker-controlled `CTL_MSG` payload.

The existing mismatch check in request processing is not a security control because it only logs when the packet source and embedded control address differ. It does not reject the request. Therefore, a spoofed embedded `ctl_addr` still reaches `sendto`.

Because UDP is connectionless and the sender can choose the embedded address without authentication, this creates a practical reflection primitive against arbitrary IPv4 targets.

## Fix Requirement

Send replies to the source address returned by `recvfrom`, not to `request.ctl_addr`.

## Patch Rationale

The patch changes the reply destination source from attacker-controlled request data to the socket address populated by `recvfrom`.

Before the patch:

```c
memcpy(&ctl_addr, &request.ctl_addr, sizeof(ctl_addr));
ctl_addr.sa_family = ntohs(request.ctl_addr.sa_family);
```

After the patch:

```c
memcpy(&ctl_addr, &response.addr, sizeof(ctl_addr));
```

`response.addr` is filled by `recvfrom` with the datagram source address. The existing `AF_INET` validation remains in place, but it now validates the real peer address used for the response rather than an attacker-selected address embedded in the payload.

This removes the reflection primitive because the daemon no longer sends responses to arbitrary addresses supplied inside `CTL_MSG`.

## Residual Risk

None

## Patch

```diff
diff --git a/talkd/talkd.c b/talkd/talkd.c
index 79fe6dd..14e6cdb 100644
--- a/talkd/talkd.c
+++ b/talkd/talkd.c
@@ -108,8 +108,7 @@ main(int argc, char *argv[])
 		request.r_name[sizeof(request.r_name) - 1] = '\0';
 		request.r_tty[sizeof(request.r_tty) - 1] = '\0';
 
-		memcpy(&ctl_addr, &request.ctl_addr, sizeof(ctl_addr));
-		ctl_addr.sa_family = ntohs(request.ctl_addr.sa_family);
+		memcpy(&ctl_addr, &response.addr, sizeof(ctl_addr));
 		ctl_addr.sa_len = sizeof(ctl_addr);
 		if (ctl_addr.sa_family != AF_INET)
 			continue;
```