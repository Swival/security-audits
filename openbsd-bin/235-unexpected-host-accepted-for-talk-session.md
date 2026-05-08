# Unexpected Host Accepted for Talk Session

## Classification

Authorization bypass, medium severity.

## Affected Locations

`usr.bin/talk/invite.c:123`

## Summary

`invite_remote()` accepted the first TCP connection to the talk session socket before validating that the peer address matched the expected remote host. If an unexpected host connected first, the code installed that accepted socket as the active global `sockt`, deleted the pending invitations, and only then displayed a warning message. The unexpected host was not rejected, so it took over the talk session.

## Provenance

Verified from the provided source, reproducer summary, and patch.

Scanner provenance: [Swival Security Scanner](https://swival.dev)

Confidence: certain.

## Preconditions

- The talk socket is listening and reachable before the expected party connects.
- An attacker-controlled remote host can connect to that socket before the expected party.

## Proof

`invite_remote()` calls `listen(sockt, 5)` and waits for an incoming connection. The vulnerable flow was:

- `accept(sockt, &rp, &rplen)` accepted the first successful connection.
- `close(sockt)` closed the listening socket.
- `sockt = new_sockt` made the accepted connection the active talk socket.
- Invitations were deleted through `ctl_transact(... DELETE ...)`.
- Only afterward, the code compared `rp.sin_addr` against `his_machine_addr`.
- On mismatch, it only called `message(rname)` with text beginning `Answering talk request from...`.

There was no `close(new_sockt)`, no rejection path, and no retry of `accept()`. After return from `invite_remote()`, the attacker-controlled descriptor was used by `set_edit_chars()` and the live `talk()` I/O path, allowing the attacker to read or inject talk-session traffic while excluding the intended peer.

## Why This Is A Real Bug

The address check occurred after the security-sensitive state transition. By the time the mismatch was detected, the listener had been closed, the accepted socket had become global session state, and invitations had been deleted. The warning message did not change control flow or revoke the connection. Therefore, the first reachable host to connect could become the active session peer regardless of whether it was the invited host.

## Fix Requirement

Validate the accepted peer address before installing the accepted descriptor as `sockt` or deleting invitations. If the peer address does not match `his_machine_addr`, close that accepted socket and continue accepting connections.

## Patch Rationale

The patch moves peer validation into the accept loop:

- Each accepted socket is checked against `his_machine_addr` immediately.
- Matching peers break out of the loop and proceed to session setup.
- Mismatched peers generate an `Ignoring talk request from...` message.
- Mismatched accepted descriptors are closed.
- The listener remains open until a valid expected peer connects.
- Invitations are deleted only after an accepted connection has passed validation.

This preserves the existing behavior for the expected peer while preventing an unexpected host from becoming the active talk session.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/talk/invite.c b/usr.bin/talk/invite.c
index fe023dd..63f6ff1 100644
--- a/usr.bin/talk/invite.c
+++ b/usr.bin/talk/invite.c
@@ -97,11 +97,33 @@ invite_remote(void)
 	message("Waiting for your party to respond");
 	signal(SIGALRM, re_invite);
 	(void) setjmp(invitebuf);
-	while ((new_sockt = accept(sockt, &rp, &rplen)) == -1) {
-		if (errno == EINTR || errno == EWOULDBLOCK ||
-		    errno == ECONNABORTED)
-			continue;
-		quit("Unable to connect with your party", 1);
+	for (;;) {
+		rplen = sizeof(struct sockaddr);
+		while ((new_sockt = accept(sockt, &rp, &rplen)) == -1) {
+			if (errno == EINTR || errno == EWOULDBLOCK ||
+			    errno == ECONNABORTED)
+				continue;
+			quit("Unable to connect with your party", 1);
+		}
+		/*
+		 * Check to see if the other guy is coming from the machine
+		 * we expect.
+		 */
+		if (his_machine_addr.s_addr ==
+		    ((struct sockaddr_in *)&rp)->sin_addr.s_addr)
+			break;
+		rphost = gethostbyaddr((char *) &((struct sockaddr_in
+		    *)&rp)->sin_addr, sizeof(struct in_addr), AF_INET);
+		if (rphost)
+			snprintf(rname, STRING_LENGTH,
+			    "Ignoring talk request from %s@%s", msg.r_name,
+			    rphost->h_name);
+		else
+			snprintf(rname, STRING_LENGTH,
+			    "Ignoring talk request from %s@%s", msg.r_name,
+			    inet_ntoa(((struct sockaddr_in *)&rp)->sin_addr));
+		message(rname);
+		close(new_sockt);
 	}
 	close(sockt);
 	sockt = new_sockt;
@@ -115,25 +137,6 @@ invite_remote(void)
 	msg.id_num = htonl(remote_id);
 	ctl_transact(his_machine_addr, msg, DELETE, &response);
 	invitation_waiting = 0;
-
-	/*
-	 * Check to see if the other guy is coming from the machine
-	 * we expect.
-	 */
-	if (his_machine_addr.s_addr !=
-	    ((struct sockaddr_in *)&rp)->sin_addr.s_addr) {
-		rphost = gethostbyaddr((char *) &((struct sockaddr_in
-		    *)&rp)->sin_addr, sizeof(struct in_addr), AF_INET);
-		if (rphost)
-			snprintf(rname, STRING_LENGTH,
-			    "Answering talk request from %s@%s", msg.r_name,
-			    rphost->h_name);
-		else
-			snprintf(rname, STRING_LENGTH,
-			    "Answering talk request from %s@%s", msg.r_name,
-			    inet_ntoa(((struct sockaddr_in *)&rp)->sin_addr));
-		message(rname);
-	}
 }
 
 /*
```