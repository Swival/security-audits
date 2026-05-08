# Malformed Forward Request Leaks Address Strings

## Classification

Denial of service, medium severity, certain confidence.

## Affected Locations

`usr.bin/ssh/mux.c:737`

## Summary

A malformed mux `MUX_C_OPEN_FWD` request with attacker-controlled address strings and an invalid port leaks the parsed `listen_addr` and `connect_addr` strings in the mux master. Repeating the request through the `ControlPath` socket can grow master memory until exhaustion.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

An attacker can connect to the mux `ControlPath` socket.

Reachability is local and constrained by the mux socket controls: the socket is created under `umask(0177)`, and accepted peers must be root or the same uid. Under the stated precondition, the malformed request is still reachable.

## Proof

In `mux_master_read_cb`, attacker-supplied mux packets are dispatched to `mux_master_process_open_fwd` when the packet type is `MUX_C_OPEN_FWD`.

In `mux_master_process_open_fwd`, the parser allocates both address strings before validating the port ranges:

```c
(r = sshbuf_get_cstring(m, &listen_addr, NULL)) != 0 ||
...
(r = sshbuf_get_cstring(m, &connect_addr, NULL)) != 0 ||
...
(lport != (u_int)PORT_STREAMLOCAL && lport > 65535) ||
(cport != (u_int)PORT_STREAMLOCAL && cport > 65535)
```

If either `lport` or `cport` is greater than `65535` and not `PORT_STREAMLOCAL`, execution enters the malformed-message branch, sets `ret = -1`, and jumps to `out`.

Before the patch, `listen_addr` and `connect_addr` had not yet been assigned into `fwd.listen_host`, `fwd.listen_path`, `fwd.connect_host`, or `fwd.connect_path`. The `out` block only freed `fwd_desc` and fields inside `fwd`, so the allocated cstrings were unreachable and leaked.

The malformed request returns `-1`, closing the mux client channel, but the mux master process continues. Repeated reconnects can accumulate leaked attacker-sized strings and exhaust memory.

## Why This Is A Real Bug

The allocation and ownership transfer are mismatched on the malformed-port path. `sshbuf_get_cstring` allocates memory into local variables, but the cleanup path only frees the `struct Forward` fields. Since the ownership transfer into `fwd` happens after the port validation, malformed ports bypass the only cleanup that can release the local address strings.

This is not a harmless client-side failure: the affected process is the long-lived mux master, and repeated malformed local requests can increase its resident memory.

## Fix Requirement

Initialize `listen_addr` and `connect_addr` to `NULL`, and free both local variables before jumping to the common `out` path when malformed parsing or port validation fails.

## Patch Rationale

The patch makes the malformed path own and release the same local allocations that were produced during parsing. Initializing the pointers to `NULL` makes unconditional cleanup safe if parsing fails before either cstring has been allocated.

The existing `out` cleanup remains responsible for `fwd` fields after normal ownership transfer. The new frees only occur before that transfer, so they do not introduce double-free behavior.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/ssh/mux.c b/usr.bin/ssh/mux.c
index db4ac80..3942d4c 100644
--- a/usr.bin/ssh/mux.c
+++ b/usr.bin/ssh/mux.c
@@ -718,7 +718,7 @@ mux_master_process_open_fwd(struct ssh *ssh, u_int rid,
 {
 	struct Forward fwd;
 	char *fwd_desc = NULL;
-	char *listen_addr, *connect_addr;
+	char *listen_addr = NULL, *connect_addr = NULL;
 	u_int ftype;
 	u_int lport, cport;
 	int r, i, ret = 0, freefwd = 1;
@@ -734,6 +734,8 @@ mux_master_process_open_fwd(struct ssh *ssh, u_int rid,
 	    (lport != (u_int)PORT_STREAMLOCAL && lport > 65535) ||
 	    (cport != (u_int)PORT_STREAMLOCAL && cport > 65535)) {
 		error_f("malformed message");
+		free(listen_addr);
+		free(connect_addr);
 		ret = -1;
 		goto out;
 	}
```