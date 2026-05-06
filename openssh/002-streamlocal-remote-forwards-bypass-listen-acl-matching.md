# streamlocal remote forwards bypass listen ACL matching

## Classification

Authorization bypass; high severity; confidence certain.

## Affected Locations

`channels.c:3211`

## Summary

Remote streamlocal forwarding authorization incorrectly treats any configured remote forwarding permission as a match for every requested Unix-domain listen path. An authenticated SSH client can request an arbitrary `streamlocal-forward@openssh.com` listener on the server when at least one restrictive remote listen ACL entry exists.

## Provenance

Verified by reproduction and patched from a Swival Security Scanner finding: https://swival.dev

## Preconditions

A restrictive remote forwarding permission list contains at least one entry, e.g. via `PermitListen` or authorized-key `permitlisten`.

## Proof

`channel_setup_remote_fwd_listener` calls `check_rfwd_permission` before creating a remote listener.

`check_rfwd_permission` evaluates user and admin remote-forward permission arrays through `remote_open_match`.

Before the patch, `remote_open_match` returned success immediately when `fwd->listen_path != NULL`:

```c
/* XXX add ACLs for streamlocal */
if (fwd->listen_path != NULL)
	return 1;
```

Because `channel_add_permission` stores restrictive remote entries as `listen_host` / `listen_port`, any nonempty permission array caused every streamlocal remote-forward path to match. The request then reached `channel_setup_fwd_listener_streamlocal`, which bound the attacker-supplied Unix-domain listener path via `unix_listener`.

## Why This Is A Real Bug

The permission check is intended to authorize remote listen targets before binding them. For TCP remote forwards, `remote_open_match` compares the requested listen host and port against configured permitted entries. For streamlocal remote forwards, the pre-patch code bypassed all path comparison and returned allow for any requested path.

This creates a real authorization bypass because a restrictive ACL entry, meant to limit remote forwards, instead enables arbitrary server-side Unix-domain listeners for authenticated clients.

## Fix Requirement

Streamlocal remote-forward authorization must compare the requested `listen_path` against permitted streamlocal entries and reject unmatched paths.

## Patch Rationale

The patch replaces the unconditional streamlocal allow with exact path matching:

```c
if (fwd->listen_path != NULL) {
	if (allowed_open->listen_path == NULL)
		return 0;
	return strcmp(allowed_open->listen_path, fwd->listen_path) == 0;
}
```

It also removes the now-stale `XXX always allowed, see remote_open_match()` comment in `channel_setup_remote_fwd_listener`, which contradicts the new matching behavior.

This preserves existing TCP matching behavior while ensuring streamlocal requests only match permission entries that explicitly contain the same `listen_path`.

## Residual Risk

None

## Patch

```diff
diff --git a/channels.c b/channels.c
index 712e816..834269d 100644
--- a/channels.c
+++ b/channels.c
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
@@ -4272,7 +4274,6 @@ channel_setup_remote_fwd_listener(struct ssh *ssh, struct Forward *fwd,
 	if (!check_rfwd_permission(ssh, fwd)) {
 		ssh_packet_send_debug(ssh, "port forwarding refused");
 		if (fwd->listen_path != NULL)
-			/* XXX always allowed, see remote_open_match() */
 			logit("Received request from %.100s port %d to "
 			    "remote forward to path \"%.100s\", "
 			    "but the request was denied.",
```