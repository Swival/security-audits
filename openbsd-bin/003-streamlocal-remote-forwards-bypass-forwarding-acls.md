# Streamlocal Remote Forwards Bypass Forwarding ACLs

## Classification

Authorization bypass; high severity; confidence certain.

## Affected Locations

`usr.bin/ssh/channels.c:3576`

`usr.bin/ssh/channels.c:4208`

`usr.bin/ssh/channels.c:4212`

`usr.bin/ssh/channels.c:4242`

`usr.bin/ssh/channels.c:4253`

`usr.bin/ssh/channels.c:4040`

`usr.bin/ssh/channels.c:4049`

`usr.bin/ssh/monitor_wrap.c:990`

## Summary

Authenticated SSH clients can create unauthorized remote Unix-domain socket listeners via streamlocal remote forwarding. The remote-forward permission check calls `remote_open_match()`, but that matcher returns success for any request with non-NULL `fwd->listen_path`, causing streamlocal remote forwards to satisfy restrictive user and admin ACL lists without path comparison.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- Server allows the remote forwarding code path.
- Server has restrictive remote forwarding ACLs, such as `PermitListen`-derived admin entries.
- Attacker is an authenticated SSH client able to request streamlocal remote forwarding.

## Proof

`channel_setup_remote_fwd_listener()` checks authorization with `check_rfwd_permission()` before listener creation.

`check_rfwd_permission()` iterates user permissions at `usr.bin/ssh/channels.c:4242` and admin permissions at `usr.bin/ssh/channels.c:4253`.

Both permission loops rely on `remote_open_match()`.

Before the patch, `remote_open_match()` contained:

```c
/* XXX add ACLs for streamlocal */
if (fwd->listen_path != NULL)
	return 1;
```

Therefore, any streamlocal remote-forward request with a non-NULL `listen_path` matched every nonempty permission list, including restrictive admin ACL entries.

After authorization incorrectly succeeds, the request reaches `channel_setup_fwd_listener_streamlocal()`, calls `unix_listener(fwd->listen_path, ...)`, and allocates an `SSH_CHANNEL_RUNIX_LISTENER`, creating a remote Unix-domain listener at the authenticated client’s chosen bindable path.

## Why This Is A Real Bug

The authorization decision is meant to constrain remote forwarding to configured listen endpoints. For TCP remote forwards, `remote_open_match()` compares the requested listen host and port against the ACL entry. For streamlocal remote forwards, it instead returned success solely because a path was present.

This makes restrictive ACLs ineffective for streamlocal remote forwards: the existence of an ACL list does not constrain the requested Unix socket path. The consequence is an unauthorized listener created on the server side, which is an authorization bypass of remote forwarding policy.

## Fix Requirement

Streamlocal remote forwards must be permitted only when the requested `fwd->listen_path` matches an explicit streamlocal ACL entry. TCP host/port matching behavior must remain unchanged.

## Patch Rationale

The patch replaces unconditional streamlocal success with exact path matching:

```c
if (fwd->listen_path != NULL) {
	if (allowed_open->listen_path == NULL)
		return 0;
	return strcmp(allowed_open->listen_path, fwd->listen_path) == 0;
}
```

This preserves the existing TCP path through host/port checks while requiring a streamlocal ACL entry to carry a `listen_path` equal to the requested path. Restrictive admin and user permission lists now correctly deny streamlocal remote forwards unless explicitly authorized.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/ssh/channels.c b/usr.bin/ssh/channels.c
index 712e816..834269d 100644
--- a/usr.bin/ssh/channels.c
+++ b/usr.bin/ssh/channels.c
@@ -4208,9 +4208,11 @@ remote_open_match(struct permission *allowed_open, struct Forward *fwd)
 	int ret;
 	char *lhost;
 
-	/* XXX add ACLs for streamlocal */
-	if (fwd->listen_path != NULL)
-		return 1;
+	if (fwd->listen_path != NULL) {
+		if (allowed_open->listen_path == NULL)
+			return 0;
+		return strcmp(allowed_open->listen_path, fwd->listen_path) == 0;
+	}
 
 	if (fwd->listen_host == NULL || allowed_open->listen_host == NULL)
 		return 0;
```