# Remote rmt Peer Controls Read Size Past Caller Limit

## Classification

High severity out-of-bounds write.

Confidence: certain.

## Affected Locations

`sbin/dump/dumprmt.c:207`

Reachable affected binary: `rrestore`.

## Summary

A malicious remote `rmt` peer can make `rmtread()` write past the caller-provided buffer by replying with an accepted byte count larger than the requested `count`.

`rmtread()` sends `R<count>\n`, trusts the `A<n>\n` value returned by `rmtreply()`, then reads `n` bytes into `buf`. Before the patch, there was no check that `n <= count`.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

The original finding named `dump`, but reproduction showed the reachable path is through `rrestore`, which builds and uses the same `sbin/dump/dumprmt.c` implementation.

## Preconditions

- `rrestore` connects to an attacker-controlled remote `rmt` service.
- The attacker can send a successful `A...` protocol reply to an `R<count>\n` read request.

## Proof

The bug is reachable in `rrestore`:

- `sbin/restore/Makefile:6` builds `dumprmt.c` into `restore` / `rrestore`.
- `sbin/restore/tape.c:147` treats `host:tape` input as a remote `rmt` source.
- `sbin/restore/tape.c:855` calls `rmtread()` into `tapebuf`.
- `sbin/restore/tape.c:959` calls `rmtread()` into `tapebuf`.
- `sbin/dump/dumprmt.c:202` sends `R<count>\n`.
- `sbin/dump/dumprmt.c:282` returns `atoi(code + 1)` for any reply beginning with `A`.
- `sbin/dump/dumprmt.c:208` reads `n` bytes into `buf` without checking that `n <= count`.

Attack flow:

```text
client:   R<count>\n
attacker: A<count+1>\n
attacker: <count+1 bytes>
```

Before the patch, `rmtread()` accepted `count + 1` as `n` and executed:

```c
read(rmtape, buf+i, n - i);
```

until `i == n`, writing beyond the caller's requested buffer capacity.

## Why This Is A Real Bug

The remote peer controls the accepted read length through the `A<n>\n` reply. The caller controls and sizes the destination buffer for `count`, not for an arbitrary peer-supplied `n`.

Because `rmtread()` requested only `count` bytes, any successful reply advertising more than `count` violates the local buffer contract. The subsequent read loop writes exactly the peer-advertised byte count into the caller buffer, creating an attacker-controlled out-of-bounds write in the `rrestore` process.

## Fix Requirement

Reject `rmtread()` replies where the accepted byte count is larger than the caller-requested `count`.

The effective required predicate is:

```c
n <= count
```

for successful read replies.

## Patch Rationale

The patch adds a bounds check immediately after `rmtcall("read", line)` returns the peer-advertised byte count:

```c
if (n > count) {
	errno = EPROTO;
	return (-1);
}
```

This preserves valid short reads and exact reads while rejecting protocol-invalid oversized read replies before any data is copied into `buf`.

`EPROTO` is appropriate because the remote peer returned a successful protocol response inconsistent with the request.

## Residual Risk

None

## Patch

```diff
diff --git a/sbin/dump/dumprmt.c b/sbin/dump/dumprmt.c
index 4bd2171..4f65897 100644
--- a/sbin/dump/dumprmt.c
+++ b/sbin/dump/dumprmt.c
@@ -201,6 +201,10 @@ rmtread(char *buf, int count)
 
 	(void)snprintf(line, sizeof(line), "R%d\n", count);
 	n = rmtcall("read", line);
+	if (n > count) {
+		errno = EPROTO;
+		return (-1);
+	}
 	if (n < 0) {
 		errno = n;
 		return (-1);
```