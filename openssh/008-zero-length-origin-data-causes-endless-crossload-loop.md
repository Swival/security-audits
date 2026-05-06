# Zero-Length Origin Data Causes Endless Crossload Loop

## Classification

Denial of service, medium severity.

Confidence: certain.

## Affected Locations

`sftp-client.c:2364`

Patch target: `sftp-client.c` in `sftp_crossload`.

## Summary

A malicious origin SFTP server can keep `sftp_crossload` running indefinitely by replying to a positive-length read request with `SSH2_FXP_DATA` containing a zero-length data string.

The client accepts `len == 0`, treats it as a short read, reissues the same unchanged read range under a new request id, and never makes progress.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched from the supplied source and reproducer evidence.

## Preconditions

- The user starts `sftp_crossload` from an attacker-controlled origin server.
- The origin server can send crafted `SSH2_FXP_DATA` replies.
- The destination server may be normal; it does not need to be malicious.

## Proof

In `sftp_crossload`, read requests are enqueued with positive `req->len` derived from `buflen`.

When the origin replies with `SSH2_FXP_DATA`, `sshbuf_get_string(msg, &data, &len)` parses an attacker-controlled data length. The existing guard only rejects:

```c
if (len > req->len)
	fatal("Received more data than asked for "
	    "%zu > %zu", len, req->len);
```

Therefore `len == 0` is accepted.

Because `len == req->len` is false for a positive request, execution enters the short-data branch:

```c
req->id = from->msg_id++;
req->len -= len;
req->offset += len;
send_read_request(from, req->id,
    req->offset, req->len,
    from_handle, from_handle_len);
```

With `len == 0`, both `req->len` and `req->offset` remain unchanged. The client sends the same read range again with a new id.

A malicious origin that repeatedly returns zero-length `SSH2_FXP_DATA` for each reissued id keeps `num_req` nonzero and preserves the main loop condition:

```c
while (num_req > 0 || max_req > 0)
```

The destination side does not prevent exploitation. The client sends zero-length writes before retrying, and OpenSSH’s server accepts zero-length writes as OK in `sftp-server.c:870`.

## Why This Is A Real Bug

A positive-length read request must either consume data, receive EOF/status, or fail. Accepting zero-length `SSH2_FXP_DATA` violates that progress invariant.

The retry path is designed for partial progress, but zero bytes is not partial progress. It preserves the pending request exactly, so the attacker controls an unbounded loop that prevents the remote-to-remote copy from completing.

## Fix Requirement

Reject zero-length `SSH2_FXP_DATA` replies for nonzero read requests, or otherwise treat them as EOF/error, before entering the short-data retry path.

## Patch Rationale

The patch adds an explicit `len == 0` fatal error after the existing oversized-data check and before logging `req->offset + len - 1`.

This prevents the non-progressing retry state and also avoids underflow in the debug range calculation for zero-length data.

The check is placed in `sftp_crossload`, the reproduced vulnerable path.

## Residual Risk

None

## Patch

```diff
diff --git a/sftp-client.c b/sftp-client.c
index 1313248..2e3354c 100644
--- a/sftp-client.c
+++ b/sftp-client.c
@@ -2556,12 +2556,14 @@ sftp_crossload(struct sftp_conn *from, struct sftp_conn *to,
 		case SSH2_FXP_DATA:
 			if ((r = sshbuf_get_string(msg, &data, &len)) != 0)
 				fatal_fr(r, "parse data");
-			debug3("Received data %llu -> %llu",
-			    (unsigned long long)req->offset,
-			    (unsigned long long)req->offset + len - 1);
 			if (len > req->len)
 				fatal("Received more data than asked for "
 				    "%zu > %zu", len, req->len);
+			if (len == 0)
+				fatal("Received zero-length data");
+			debug3("Received data %llu -> %llu",
+			    (unsigned long long)req->offset,
+			    (unsigned long long)req->offset + len - 1);
 
 			/* Write this chunk out to the destination */
 			sshbuf_reset(msg);
```