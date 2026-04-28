# Short Write Reported Successful

## Classification

Data integrity bug, medium severity.

Confidence: certain.

## Affected Locations

`modules/generators/mod_cgid.c:424`

## Summary

`mod_cgid` treated positive short writes on the cgid Unix-domain socket as complete success. `sock_write()` and `sock_writev()` only checked for negative return values, so `write()`, `writev()`, or `sendmsg()` returning fewer bytes than requested caused the caller to believe a full protocol message had been sent while the cgid daemon received only a prefix.

## Provenance

Reported and reproduced from Swival Security Scanner output: https://swival.dev

## Preconditions

- `write()`, `writev()`, or `sendmsg()` returns a positive byte count smaller than requested.
- The path uses the cgid socket protocol, reachable from CGI, SSI, or GETPID request handling.

## Proof

Request data is assembled in `send_req()` and `get_cgi_pid()`, then sent through `sock_write()` or `sock_writev()`.

In the affected implementation:

- `sock_write()` calls `write(fd, buf, buf_size)` and returns `APR_SUCCESS` for any non-negative `rc`.
- `sock_writev()` calls `writev()` or `sendmsg()` and returns `APR_SUCCESS` for any non-negative `rc`.
- Neither helper verifies that `rc == buf_size` or that all iovec bytes were written.

The reproduced platform behavior confirmed the precondition: a blocking `AF_UNIX` stream `write()` with a small send buffer, interrupted by a signal, returned `4096` for a `1048576` byte request with `errno=0`. That is a positive short write and exactly the case the original code reported as success.

Affected flows:

- `send_req()` sends cgid request headers, path fields, arguments, environment entries, and optional rlimits through `sock_writev()` / `sock_write()`.
- `get_cgi_pid()` sends a `cgid_req_t` through `sock_write()` before waiting for the daemon response.
- The daemon expects complete protocol fields via `sock_readhdr()` / `sock_read()`, so a truncated send can corrupt framing or block the peer.

## Why This Is A Real Bug

POSIX allows stream socket writes to complete with a positive byte count smaller than requested. The reproduced `AF_UNIX` stream behavior demonstrates this is practical, not theoretical.

Because the cgid socket protocol has fixed-size and length-prefixed fields, silently accepting a short write breaks sender/receiver agreement:

- The handler believes the full request was sent.
- The daemon receives a truncated request and reads subsequent bytes as the wrong field, rejects the request, or waits for bytes that will never arrive.
- `get_cgi_pid()` can deadlock the handler and the single-threaded cgid daemon when the GETPID request is truncated before the daemon can process it.

This is reachable on CGI and SSI request paths using the cgid socket.

## Fix Requirement

Writes must either:

- Loop until the entire buffer or iovec set has been written, preserving correct protocol framing.
- Return an error such as `APR_INCOMPLETE` if forward progress is impossible.

A positive short write must not be reported as `APR_SUCCESS`.

## Patch Rationale

The patch changes `sock_write()` to maintain a current pointer and remaining byte count, retrying after each positive partial write until `buf_size` reaches zero. It continues to retry `EINTR`, returns `errno` for negative failures, and returns `APR_INCOMPLETE` if `write()` returns zero without progress.

The patch changes `sock_writev()` to loop over the remaining iovec data. After each successful `writev()` or `sendmsg()` call, it:

- Clears `auxfd` so file descriptor passing is attempted only on the first send.
- Advances past fully written iovec entries.
- Adjusts the base pointer and length of a partially written iovec.
- Continues until all iovecs are consumed.
- Returns `APR_INCOMPLETE` if a zero-byte write occurs.

This preserves the existing error handling while ensuring callers only receive `APR_SUCCESS` after the complete cgid protocol message has been sent.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/generators/mod_cgid.c b/modules/generators/mod_cgid.c
index a0ef2b5..5af27bf 100644
--- a/modules/generators/mod_cgid.c
+++ b/modules/generators/mod_cgid.c
@@ -430,13 +430,21 @@ static apr_status_t sock_read(int fd, void *vbuf, size_t buf_size)
  */
 static apr_status_t sock_write(int fd, const void *buf, size_t buf_size)
 {
+    const char *pos = buf;
     int rc;
 
-    do {
-        rc = write(fd, buf, buf_size);
-    } while (rc < 0 && errno == EINTR);
-    if (rc < 0) {
-        return errno;
+    while (buf_size) {
+        do {
+            rc = write(fd, pos, buf_size);
+        } while (rc < 0 && errno == EINTR);
+        if (rc < 0) {
+            return errno;
+        }
+        if (rc == 0) {
+            return APR_INCOMPLETE;
+        }
+        pos += rc;
+        buf_size -= rc;
     }
 
     return APR_SUCCESS;
@@ -457,41 +465,56 @@ static apr_status_t sock_writev(int fd, int auxfd, request_rec *r, int count, ..
     }
     va_end(ap);
 
+    while (count) {
 #ifndef HAVE_CGID_FDPASSING
-    do {
-        rc = writev(fd, vec, count);
-    } while (rc < 0 && errno == EINTR);
+        do {
+            rc = writev(fd, vec, count);
+        } while (rc < 0 && errno == EINTR);
 #else
-    {
-        struct msghdr msg = { 0 };
-        struct cmsghdr *cmsg;
-        union { /* union for alignment */
-            char buf[CMSG_SPACE(sizeof(int))];
-            struct cmsghdr align;
-        } u;
+        {
+            struct msghdr msg = { 0 };
+            struct cmsghdr *cmsg;
+            union { /* union for alignment */
+                char buf[CMSG_SPACE(sizeof(int))];
+                struct cmsghdr align;
+            } u;
 
-        msg.msg_iov = vec;
-        msg.msg_iovlen = count;
+            msg.msg_iov = vec;
+            msg.msg_iovlen = count;
 
-        if (auxfd) {
-            msg.msg_control = u.buf;
-            msg.msg_controllen = sizeof(u.buf);
+            if (auxfd) {
+                msg.msg_control = u.buf;
+                msg.msg_controllen = sizeof(u.buf);
 
-            cmsg = CMSG_FIRSTHDR(&msg);
-            cmsg->cmsg_level = SOL_SOCKET;
-            cmsg->cmsg_type = SCM_RIGHTS;
-            cmsg->cmsg_len = CMSG_LEN(sizeof(int));
-            *((int *) CMSG_DATA(cmsg)) = auxfd;
+                cmsg = CMSG_FIRSTHDR(&msg);
+                cmsg->cmsg_level = SOL_SOCKET;
+                cmsg->cmsg_type = SCM_RIGHTS;
+                cmsg->cmsg_len = CMSG_LEN(sizeof(int));
+                *((int *) CMSG_DATA(cmsg)) = auxfd;
+            }
+
+            do {
+                rc = sendmsg(fd, &msg, 0);
+            } while (rc < 0 && errno == EINTR);
+        }
+#endif
+        if (rc < 0) {
+            return errno;
+        }
+        if (rc == 0) {
+            return APR_INCOMPLETE;
         }
 
-        do {
-            rc = sendmsg(fd, &msg, 0);
-        } while (rc < 0 && errno == EINTR);
-    }
-#endif
-    
-    if (rc < 0) {
-        return errno;
+        auxfd = 0;
+        while (count && rc >= vec[0].iov_len) {
+            rc -= vec[0].iov_len;
+            vec++;
+            count--;
+        }
+        if (count && rc) {
+            vec[0].iov_base = (char *)vec[0].iov_base + rc;
+            vec[0].iov_len -= rc;
+        }
     }
 
     return APR_SUCCESS;
```