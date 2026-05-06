# pipelining clears PASV rewrite state

## Classification

Low severity information disclosure.

## Affected Locations

`ftp-proxy/ftp-proxy.c:144`

## Summary

A pipelined FTP command can clear pending passive-mode rewrite state before the server returns the corresponding `227`/`229` reply. In fixed-server mode, this causes the proxy to forward the backend server's raw passive address/port to the client instead of rewriting it to the original server address.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- `ftp-proxy` runs with `fixed_server` enabled.
- The proxy permits client command pipelining.
- A client sends `PASV` or `EPSV` followed by another command before the passive-mode server reply is parsed.

## Proof

`client_parse()` resets `s->cmd` to `CMD_NONE` and `s->port` to `0` at the start of every client command.

`PASV` sets `s->cmd = CMD_PASV` in `client_parse_cmd()`, but a following pipelined command enters `client_parse()` before the server's `227` reply is processed and clears that state.

`server_parse()` only rewrites passive replies through `allow_data_connection()` when:

```c
s->cmd == CMD_PASV && strncmp("227 ", linebuf, 4) == 0
```

or:

```c
s->cmd == CMD_EPSV && strncmp("229 ", linebuf, 4) == 0
```

With `s->cmd == CMD_NONE`, `server_parse()` falls through and forwards `linebuf` unchanged to the client.

In fixed-server mode, the expected rewrite path is `allow_data_connection()`, which chooses `s->orig_server_ss` as `orig_sa` and calls `proxy_reply()` to replace the passive reply address. Skipping that path exposes the backend's raw passive address/port.

## Why This Is A Real Bug

The proxy tracks command/reply context with a single scalar `s->cmd`. Because client and server parsing are asynchronous and client command pipelining is allowed, a later client command can overwrite the state needed to interpret an earlier server reply.

This violates the proxy's fixed-server behavior: passive replies should be rewritten so the client sees the original server address, not the fixed backend address. The disclosed value is externally observable by a remote FTP client.

## Fix Requirement

Preserve pending `PASV`/`EPSV` state until the corresponding server reply is parsed. A later client command must not clear passive-mode rewrite state before `server_parse()` has a chance to process the matching `227` or `229` reply.

## Patch Rationale

The patch removes the unconditional reset from the start of `client_parse()`:

```diff
-	/* Reset any previous command. */
-	s->cmd = CMD_NONE;
-	s->port = 0;
```

This prevents unrelated pipelined client commands from clearing pending passive-mode state. Existing cleanup remains in `server_parse()` and `allow_data_connection()`, so command state is still cleared after server-side handling completes.

## Residual Risk

None

## Patch

```diff
diff --git a/ftp-proxy/ftp-proxy.c b/ftp-proxy/ftp-proxy.c
index efb52ac..1f33b64 100644
--- a/ftp-proxy/ftp-proxy.c
+++ b/ftp-proxy/ftp-proxy.c
@@ -142,10 +142,6 @@ client_error(struct bufferevent *bufev, short what, void *arg)
 int
 client_parse(struct session *s)
 {
-	/* Reset any previous command. */
-	s->cmd = CMD_NONE;
-	s->port = 0;
-
 	/* Commands we are looking for are at least 4 chars long. */
 	if (linelen < 4)
 		return (1);
```