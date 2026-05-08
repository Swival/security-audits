# Malformed HELLO Extension Leaks Name Allocation

## Classification

Denial of service, medium severity. Confidence: certain.

## Affected Locations

`usr.bin/ssh/mux.c:287`

## Summary

A malformed mux `HELLO` extension can leak the allocated extension name in the multiplex master. A local process with access to an active `ControlPath` socket can repeat the malformed handshake across connections and exhaust the mux master process memory.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- The SSH multiplex master is listening on a `ControlPath` socket.
- An attacker-controlled local process can connect to that socket.

## Proof

`mux_master_read_cb` creates mux channel state and dispatches client packets to `mux_master_process_hello`.

In `mux_master_process_hello`, the extension loop parses a name followed by a string value:

```c
if ((r = sshbuf_get_cstring(m, &name, NULL)) != 0 ||
    (r = sshbuf_get_string_direct(m, NULL, &value_len)) != 0) {
        error_fr(r, "parse extension");
        return -1;
}
```

`sshbuf_get_cstring(m, &name, NULL)` allocates `name`. If the following `sshbuf_get_string_direct(m, NULL, &value_len)` fails because the value string is malformed, the function returns `-1` without freeing `name`.

The failing handler return closes only the current mux-control channel. Cleanup releases the channel mux context, but not the leaked extension name allocation. The mux master listener remains alive for later `ControlPath` connections.

The packet size cap is 256 KiB, so each connection can leak roughly one maximum-sized extension name. Repeated malformed `HELLO` packets can therefore exhaust memory in the long-lived mux master.

## Why This Is A Real Bug

The allocation and ownership are local and unambiguous: after `sshbuf_get_cstring` succeeds, `name` must be freed on every exit path from the loop iteration. The success path already calls `free(name)`, proving ownership expectations. The parse-failure branch omits that release and returns immediately, leaving no later code able to free it.

The mux master persists after the malformed client channel is closed, so the leak accumulates across repeated accessible socket connections instead of being reclaimed by process exit.

## Fix Requirement

Free `name` before returning from the extension parse error branch.

## Patch Rationale

The patch adds `free(name)` in the combined parse-failure branch. This is safe because:

- `name` is initialized to `NULL` on each loop iteration.
- `free(NULL)` is valid if `sshbuf_get_cstring` itself failed before allocation.
- If `sshbuf_get_cstring` succeeded and the value parse failed, the allocated name is released.
- The existing success-path ownership and behavior are unchanged.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/ssh/mux.c b/usr.bin/ssh/mux.c
index db4ac80..00d7bdc 100644
--- a/usr.bin/ssh/mux.c
+++ b/usr.bin/ssh/mux.c
@@ -284,6 +284,7 @@ mux_master_process_hello(struct ssh *ssh, u_int rid,
 		if ((r = sshbuf_get_cstring(m, &name, NULL)) != 0 ||
 		    (r = sshbuf_get_string_direct(m, NULL, &value_len)) != 0) {
 			error_fr(r, "parse extension");
+			free(name);
 			return -1;
 		}
 		if (strcmp(name, "info") == 0) {
```