# Partial Control Command Blocks Transfer Worker

## Classification

Denial of service, medium severity.

## Affected Locations

`src/data.c:899`

## Summary

An authenticated FTP client with an active data transfer can send only 1-4 bytes on the control connection and stall the session worker. The worker polls the control channel before each transfer chunk, observes that some control data is readable, then peeks with `recv(..., MSG_PEEK|MSG_WAITALL)` for a 5-byte buffer. Because `select()` only proves that at least one byte is readable, `MSG_WAITALL` can block until all 5 bytes arrive, stopping data transfer progress.

## Provenance

Verified from the supplied reproduction and patch details. Originally identified by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The attacker is an authenticated FTP client.
- The authenticated session has an active data transfer.
- The attacker can write partial data to the FTP control connection during that transfer.

## Proof

The reproduced execution path is:

- `pr_data_xfer()` calls `poll_ctrl()` before each data transfer chunk at `src/data.c:1257`.
- `poll_ctrl()` polls the control connection and, when readable control-channel data is reported and `SF_ABORT` is not set, calls `peek_is_abor_cmd()` at `src/data.c:1033`.
- `peek_is_abor_cmd()` first calls `select()` with a one-second timeout at `src/data.c:969`.
- A readable result from `select()` only guarantees at least one byte is available.
- The function then calls `recv(fd, buf, sizeof(buf), MSG_PEEK|MSG_WAITALL)` for a 5-byte buffer at `src/data.c:998`.
- On a blocking control socket, `MSG_WAITALL` waits for all requested bytes unless interrupted, closed, or errored.
- Accepted/opened connections are restored to blocking mode by `pr_inet_openrw()` at `src/inet.c:1960`.
- Therefore, a client that sends only 1-4 control bytes during an active transfer can block the session worker inside `recv()` before further data read/write progress occurs.

## Why This Is A Real Bug

The code intentionally performs an opportunistic peek to detect `ABOR` during a transfer, but the implementation is not opportunistic: `MSG_WAITALL` converts the peek into a blocking wait for five bytes. The control socket is blocking, and the attacker controls whether the remaining bytes are sent. This lets one authenticated client stop its own transfer worker indefinitely, or until the client sends more bytes, closes the connection, or a configured timeout disconnects the session.

## Fix Requirement

The ABOR peek must not wait for bytes that are not already available after readiness has been observed. The `recv()` call must avoid `MSG_WAITALL`, or otherwise use nonblocking semantics after `select()`.

## Patch Rationale

The patch removes `MSG_WAITALL` from both `recv()` calls in `peek_is_abor_cmd()`:

```c
len = recv(fd, buf, sizeof(buf), MSG_PEEK);
```

This preserves the intended behavior of peeking at currently available control-channel bytes while preventing the worker from blocking until the full 5-byte buffer is filled. Partial input is handled by the existing length-based comparison:

```c
strncasecmp(buf, "ABOR\r", len) == 0
```

Thus, ABOR detection remains opportunistic, and incomplete non-ABOR control input no longer stalls transfer progress.

## Residual Risk

None

## Patch

`005-partial-control-command-blocks-transfer-worker.patch`

```diff
diff --git a/src/data.c b/src/data.c
index c53f29f88..a146b02d6 100644
--- a/src/data.c
+++ b/src/data.c
@@ -988,20 +988,17 @@ static int peek_is_abor_cmd(void) {
   }
 
   /* If we reach here, the peer must have sent something.  Let's see what it
-   * might be.  Chances are that we received at least 5 bytes, but to be
-   * defensive, we use MSG_WAITALL anyway.  TCP allows for sending one byte
-   * at time, if need be.  The shortest FTP command is 5 bytes, e.g. "CCC\r\n".
-   * ABOR would be 6 bytes, but we do not want to block until we see 6 bytes;
-   * we're peeking opportunistically, and optimistically.
+   * might be.  TCP allows for sending one byte at time, if need be, so avoid
+   * waiting for the full buffer and just peek at what is currently available.
    */
   memset(&buf, 0, sizeof(buf));
-  len = recv(fd, buf, sizeof(buf), MSG_PEEK|MSG_WAITALL);
+  len = recv(fd, buf, sizeof(buf), MSG_PEEK);
   while (len < 0) {
     int xerrno = errno;
 
     if (xerrno == EINTR) {
       pr_signals_handle();
-      len = recv(fd, &buf, sizeof(buf), MSG_PEEK|MSG_WAITALL);
+      len = recv(fd, &buf, sizeof(buf), MSG_PEEK);
       continue;
     }
```