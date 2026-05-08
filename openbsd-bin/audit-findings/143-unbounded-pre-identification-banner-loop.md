# Unbounded Pre-Identification Banner Loop

## Classification

denial of service, medium severity, certain confidence

## Affected Locations

`usr.bin/ssh/ssh-keyscan.c:464`

## Summary

`ssh-keyscan` can be kept busy indefinitely by an attacker-controlled SSH endpoint that continuously sends newline-terminated, non-SSH banner lines before the SSH protocol identification string.

The vulnerable path is in `congreet()`, where pre-identification banner lines are read and ignored until a line starts with `SSH-`. The scan timeout deadline is not enforced inside that loop, and the packet timeout is only installed after a valid SSH banner is received.

## Provenance

Verified from reproduced evidence and patched source.

Scanner provenance: Swival Security Scanner, https://swival.dev

## Preconditions

- The victim runs `ssh-keyscan` against an attacker-controlled SSH endpoint.
- The attacker-controlled endpoint sends endless newline-terminated lines that do not begin with `SSH-`.

## Proof

`conloop()` dispatches readable sockets to `conread()`, which calls `congreet()` for the descriptor.

Inside `congreet()`, the pre-identification loop repeatedly reads one line at a time:

- The outer loop repeats until `strncmp(buf, "SSH-", 4) == 0`.
- Non-SSH lines cause the loop to continue.
- The comment explicitly permits an arbitrarily large preceding banner.
- No elapsed connection timeout is checked inside this loop.
- `ssh_packet_set_timeout()` is called only after a valid SSH banner is accepted.

Each byte is read with `atomicio(read, s, cp, 1)`. On nonblocking sockets, `atomicio()` waits with `poll(..., -1)` on `EAGAIN`, so slow or stalled banner delivery can also bypass the scan timeout while execution remains inside `congreet()`.

Result: one malicious endpoint can keep the single-threaded `ssh-keyscan` process stuck in `congreet()`, preventing other connection handling and timeout recycling.

## Why This Is A Real Bug

`ssh-keyscan` maintains a per-connection deadline in `c->c_ts`, but the deadline is only effective when control returns to `conloop()` timeout handling. The malicious banner stream prevents that return.

Because the vulnerable read loop accepts unbounded pre-identification data and does not enforce elapsed time during that phase, an attacker can cause persistent resource occupation from a single scanned host. This is attacker-triggered denial of service.

## Fix Requirement

Enforce the existing connection timeout while reading pre-identification banner lines, before continuing another iteration of the banner-ignore loop.

## Patch Rationale

The patch adds a `struct timespec now` local and checks the current monotonic time against `c->c_ts` at the start of each pre-identification banner iteration.

If the deadline has elapsed, the connection is recycled and `congreet()` returns. This reuses the existing timeout semantics and prevents endless non-SSH banner lines from monopolizing the process.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/ssh/ssh-keyscan.c b/usr.bin/ssh/ssh-keyscan.c
index 8b169db..bf6bf47 100644
--- a/usr.bin/ssh/ssh-keyscan.c
+++ b/usr.bin/ssh/ssh-keyscan.c
@@ -433,6 +433,7 @@ congreet(int s)
 	char buf[256], *cp;
 	char remote_version[sizeof buf];
 	size_t bufsiz;
+	struct timespec now;
 	con *c = &fdcon[s];
 
 	/* send client banner */
@@ -459,6 +460,11 @@ congreet(int s)
 	 * in multiple iterations of the outer loop).
 	 */
 	for (;;) {
+		monotime_ts(&now);
+		if (timespeccmp(&now, &c->c_ts, >=)) {
+			conrecycle(s);
+			return;
+		}
 		memset(buf, '\0', sizeof(buf));
 		bufsiz = sizeof(buf);
 		cp = buf;
```