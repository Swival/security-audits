# Malformed Lock Request Terminates Agent

## Classification

denial of service, medium severity, certain confidence

## Affected Locations

`ssh-agent.c:1465`

## Summary

A malformed `SSH_AGENTC_LOCK` or `SSH_AGENTC_UNLOCK` request without the required password string causes `ssh-agent` to call `fatal_fr()` and exit. An attacker that can write raw agent protocol messages to a forwarded agent socket can terminate the local agent process, denying all subsequent key operations.

## Provenance

Verified from supplied source, reproducer evidence, and patch. Initially reported by Swival Security Scanner: https://swival.dev

## Preconditions

- Attacker can write agent protocol messages to a forwarded agent socket.
- User has agent forwarding enabled to an attacker-controlled or compromised remote host.

## Proof

`process_message()` consumes the message type byte and dispatches `SSH_AGENTC_LOCK` and `SSH_AGENTC_UNLOCK` directly to `process_lock_agent()`.

A 5-byte agent message is sufficient:

```text
00 00 00 01 16
```

This encodes a one-byte message body containing only the request type. After the type byte is consumed, `e->request` is empty. `process_lock_agent()` then calls:

```c
sshbuf_get_cstring(e->request, &passwd, &pwlen)
```

Because fewer than four bytes remain for the string length, this returns `SSH_ERR_MESSAGE_INCOMPLETE`. The vulnerable code handles that parse error with:

```c
fatal_fr(r, "parse");
```

`fatal_fr()` reaches `sshfatal()`, which calls `cleanup_exit(255)`, terminating the `ssh-agent` process.

Forwarded-agent plumbing passes remote channel data to the local agent socket without protocol filtering: `client_request_agent()` opens the local auth socket, creates a raw channel, and channel data is appended to the socket output.

## Why This Is A Real Bug

Malformed client-controlled protocol input must not terminate a long-lived authentication agent. Other agent request handlers treat malformed input as request failure and keep the process alive. Here, one incomplete lock/unlock request deterministically exits the agent, making loaded keys unavailable and breaking future authentication/signing operations.

## Fix Requirement

On lock/unlock password parse failure, return an agent failure response and continue processing instead of calling a fatal termination path.

## Patch Rationale

The patch replaces fatal handling of `sshbuf_get_cstring()` parse errors with normal request failure handling:

```c
error_fr(r, "parse");
send_status(e, 0);
return;
```

This preserves the existing success/failure semantics for lock and unlock requests while preventing attacker-controlled malformed input from killing the process.

## Residual Risk

None

## Patch

```diff
diff --git a/ssh-agent.c b/ssh-agent.c
index f83dd03..fb0b866 100644
--- a/ssh-agent.c
+++ b/ssh-agent.c
@@ -1457,13 +1457,11 @@ process_lock_agent(SocketEntry *e, int lock)
 	size_t pwlen;
 
 	debug2_f("entering");
-	/*
-	 * This is deliberately fatal: the user has requested that we lock,
-	 * but we can't parse their request properly. The only safe thing to
-	 * do is abort.
-	 */
-	if ((r = sshbuf_get_cstring(e->request, &passwd, &pwlen)) != 0)
-		fatal_fr(r, "parse");
+	if ((r = sshbuf_get_cstring(e->request, &passwd, &pwlen)) != 0) {
+		error_fr(r, "parse");
+		send_status(e, 0);
+		return;
+	}
 	if (pwlen == 0) {
 		debug("empty password not supported");
 	} else if (locked && !lock) {
```