# Short writev reported successful

## Classification

Data integrity bug, medium severity. Confidence: certain.

## Affected Locations

`modules/generators/mod_cgid.c:479`

## Summary

`mod_cgid` sends CGI request metadata to the cgid daemon with `sock_writev()`. The original implementation treated any nonnegative `writev()` or `sendmsg()` return value as `APR_SUCCESS`, even when fewer bytes were written than requested. A short write can therefore make the request handler believe a complete CGI request was delivered while the daemon receives only a truncated request stream.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

## Preconditions

`writev()` or `sendmsg()` writes fewer bytes than requested without returning an error.

## Proof

`send_req()` builds the daemon request from `cgid_req_t req`, `r->filename`, `argv0`, `r->uri`, optional `r->args`, and environment variables, then calls `sock_writev()`.

In the affected implementation, `sock_writev()` calls `writev()` or `sendmsg()` once and returns `APR_SUCCESS` for any `rc >= 0`. It does not compare `rc` against the total requested iovec byte count and does not retry the unwritten tail.

The daemon side, `get_req()`, expects the stream to contain the complete request header and all following variable-length fields. If the handler reports success after a partial write, `get_req()` reads a truncated stream as though it were a full request, causing misparsed CGI metadata/environment, CGI dispatch failure, or blocking while the handler waits for a PID/response.

The reproduced OS behavior confirms the prerequisite is realistic: a blocking socketpair `writev()` interrupted after partial progress returned `8192` for a `67108864` byte request, and `sendmsg()` returned `8192` for a `33554432` byte request.

## Why This Is A Real Bug

POSIX permits `writev()` and `sendmsg()` to return a positive byte count smaller than the requested total. The original code conflates positive partial completion with full completion. Because the cgid protocol is a length-sensitive byte stream and the reader consumes fields in a fixed order, losing any suffix of a request corrupts protocol framing and request semantics.

Reachability is normal request handling:

`cgid_handler()` calls `send_req()` for CGI requests and proceeds on `APR_SUCCESS`.

`include_cmd()` calls `send_req()` for SSI command execution.

Thus no unusual code path is required beyond a legitimate short write.

## Fix Requirement

`send_req()` must not treat a partial vectored write as complete. `sock_writev()` must either:

- loop until all iovec bytes are written, correctly advancing through partially written iovec entries; or
- return an error such as `APR_INCOMPLETE` when a short write occurs.

## Patch Rationale

The patch updates `sock_writev()` to loop while iovec entries remain. After each successful `writev()` or `sendmsg()`, it consumes the returned byte count across the iovec array, adjusting `iov_base` and `iov_len` when the write ends in the middle of an entry. This preserves the existing call sites while ensuring `APR_SUCCESS` means the complete vector was sent.

For fd-passing builds, the auxiliary descriptor is sent only on the first `sendmsg()` call by clearing `auxfd` after the initial attempt. This avoids duplicating descriptor transfer on retries for the remaining byte stream.

A zero-byte write returns `APR_INCOMPLETE`, preventing an infinite loop and correctly reporting that progress stopped before the vector was fully sent.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/generators/mod_cgid.c b/modules/generators/mod_cgid.c
index a0ef2b5..e9258e9 100644
--- a/modules/generators/mod_cgid.c
+++ b/modules/generators/mod_cgid.c
@@ -457,41 +457,58 @@ static apr_status_t sock_writev(int fd, int auxfd, request_rec *r, int count, ..
     }
     va_end(ap);
 
+    while (count > 0) {
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
+            auxfd = 0;
+        }
+#endif
+
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
+        while (rc > 0) {
+            if ((apr_size_t)rc < vec[0].iov_len) {
+                vec[0].iov_base = (char *)vec[0].iov_base + rc;
+                vec[0].iov_len -= rc;
+                break;
+            }
+            rc -= vec[0].iov_len;
+            vec++;
+            count--;
+        }
     }
 
     return APR_SUCCESS;
```