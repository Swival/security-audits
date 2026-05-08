# Oversized Group imsg Overwrites Stack Request

## Classification

High severity memory corruption.

## Affected Locations

- `usr.sbin/ypldap/ypldap.c:341`
- `usr.sbin/ypldap/ypldap.c:418`

## Summary

`main_dispatch_client()` accepts `IMSG_GRP_ENTRY` messages from the ldapclient IPC channel and copies the message payload into a fixed stack `struct idm_req ir` without validating the payload length. A malicious child process or IPC peer can send an oversized group-entry imsg and overwrite past `ir` on the ypldap parent stack.

## Provenance

Found by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The child can send imsgs on `pipe_main2client`.
- The attacker controls or compromises the ldapclient child process, or otherwise controls the child-side imsg socket.
- The parent processes an update sequence where `update_trashed == 0`.

## Proof

`main_dispatch_client()` reads imsgs from `env->sc_iev`, whose imsg buffer is initialized on `pipe_main2client[0]` after `ldapclient(pipe_main2client)` creates the child-side IPC channel.

For `IMSG_GRP_ENTRY`, the parent declares a fixed stack object:

```c
struct idm_req ir;
```

Before the patch, the group-entry handler copied the full imsg payload into that stack object:

```c
(void)memcpy(&ir, imsg.data, n - IMSG_HEADER_SIZE);
```

No check constrained `n - IMSG_HEADER_SIZE` to `sizeof(ir)`. `struct idm_req` contains a uid/gid key plus `ir_line[1024]`, while imsg framing permits larger messages up to `MAX_IMSGSIZE`. `imsg_get()` rejects messages that are smaller than the imsg header or larger than the imsg maximum, but it does not enforce per-message payload sizes.

A malicious child can send:

1. `IMSG_START_UPDATE`, setting `update_trashed` to `0`.
2. `IMSG_GRP_ENTRY` with an oversized payload, such as 2048 bytes.

The parent then reaches the group-entry case and writes past `ir` on the stack before calling `strdup(ir.ir_line)`.

## Why This Is A Real Bug

The parent trusts a lower-privileged IPC peer for the payload length of a stack copy. The honest ldapclient path normally sends bounded `struct idm_req` payloads, but that does not protect the parent from a malicious or compromised child process. The vulnerable copy crosses a privilege-separation boundary and can corrupt parent stack data, causing at minimum a daemon crash and potentially corrupting control data in the less-confined parent process.

## Fix Requirement

Reject `IMSG_GRP_ENTRY` payloads whose length is not exactly `sizeof(struct idm_req)`, and copy only `sizeof(struct idm_req)` bytes into the stack object.

## Patch Rationale

The patch adds an exact payload-size check before the `memcpy()` in the `IMSG_GRP_ENTRY` handler:

```c
if (n - IMSG_HEADER_SIZE != sizeof(ir))
	break;
(void)memcpy(&ir, imsg.data, sizeof(ir));
```

This prevents oversized payloads from overflowing `ir`, prevents undersized payloads from leaving fields partially uninitialized, and preserves the expected wire contract that group-entry messages contain exactly one `struct idm_req`.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/ypldap/ypldap.c b/usr.sbin/ypldap/ypldap.c
index ccabd97..3a17bc3 100644
--- a/usr.sbin/ypldap/ypldap.c
+++ b/usr.sbin/ypldap/ypldap.c
@@ -418,7 +418,9 @@ main_dispatch_client(int fd, short events, void *p)
 			if (env->update_trashed)
 				break;
 
-			(void)memcpy(&ir, imsg.data, n - IMSG_HEADER_SIZE);
+			if (n - IMSG_HEADER_SIZE != sizeof(ir))
+				break;
+			(void)memcpy(&ir, imsg.data, sizeof(ir));
 			if ((ge = calloc(1, sizeof(*ge))) == NULL ||
 			    (ge->ge_line = strdup(ir.ir_line)) == NULL) {
 				/*
```