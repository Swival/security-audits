# Zero-Length Read Data Causes Endless Download Loop

## Classification

Denial of service, medium severity. Confidence: certain.

## Affected Locations

`sftp-client.c:1699`

## Summary

A malicious SFTP server can keep a client download alive indefinitely by replying to positive-length `SSH2_FXP_READ` requests with zero-length `SSH2_FXP_DATA` packets. The client accepts `len == 0`, makes no offset or length progress, and reissues the same read range under a new request id forever.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

The client downloads a file from a malicious SFTP server.

## Proof

- `sftp_download()` opens the remote file and queues positive-length `SSH2_FXP_READ` requests.
- `SSH2_FXP_DATA` is parsed with `sshbuf_get_string()` and stored in `len`.
- The only original bounds check rejected `len > req->len`; `len == 0` was accepted.
- Because `len != req->len`, the short-data branch executes.
- `req->len -= len` and `req->offset += len` leave the request unchanged when `len == 0`.
- `send_read_request()` then reissues the same range with a new request id.
- `num_req` is not decremented, `max_req` remains active unless EOF `STATUS` is received, and the outer transfer loop continues.
- A malicious server can repeat zero-length `DATA` replies for each new id to hang the client download indefinitely.

## Why This Is A Real Bug

A zero-length `SSH2_FXP_DATA` response to a positive-length read cannot advance the transfer. The existing retry logic assumes short reads make positive progress; that invariant is false for `len == 0`. Since EOF is represented by `SSH2_FXP_STATUS` with `SSH2_FX_EOF`, not by an empty data payload in this code path, accepting zero-length data lets an attacker force a non-progressing retry loop.

## Fix Requirement

Reject zero-length `SSH2_FXP_DATA` replies for outstanding nonzero read requests, or otherwise convert them into terminal EOF/error handling so the transfer loop cannot retry the same range indefinitely.

## Patch Rationale

The patch adds an explicit `len == 0` check immediately after the existing oversized-data check in `sftp_download()`. This preserves valid short-read behavior for positive lengths while terminating the invalid no-progress case before request state is updated or the same read range is reissued.

## Residual Risk

None

## Patch

```diff
diff --git a/sftp-client.c b/sftp-client.c
index 1313248..26fa827 100644
--- a/sftp-client.c
+++ b/sftp-client.c
@@ -1724,6 +1724,8 @@ sftp_download(struct sftp_conn *conn, const char *remote_path,
 			if (len > req->len)
 				fatal("Received more data than asked for "
 				    "%zu > %zu", len, req->len);
+			if (len == 0)
+				fatal("Received zero-length data");
 			lmodified = 1;
 			if ((lseek(local_fd, req->offset, SEEK_SET) == -1 ||
 			    atomicio(vwrite, local_fd, data, len) != len) &&
```