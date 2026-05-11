# Unauthenticated Loopback Stdin Bridge Exposes Stdin

## Classification

Information disclosure, medium severity. Confidence: certain.

## Affected Locations

- `src/tool_doswin.c:714` (`win_stdin_thread_func`)
- `src/tool_doswin.c:765` (`win32_stdin_read_thread`)

## Summary

In Windows `USE_WINSOCK` builds, `win32_stdin_read_thread()` creates a loopback TCP listener for stdin forwarding, starts the stdin reader thread, and only then connects its own `socket_r`. The thread accepts the first loopback connection without authenticating the peer. A lower-privileged local process that wins this race receives bytes read from the victim process's stdin.

## Provenance

Reported and validated by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- Windows build with `USE_WINSOCK`.
- `win32_stdin_read_thread()` is used with readable stdin.
- The user-facing path is stdin upload, where `setup_upload_from_stdin()` calls this bridge when `per->uploadfile == "."`.

## Proof

The vulnerable flow is:

- `win32_stdin_read_thread()` binds a TCP listener to `INADDR_LOOPBACK` on an ephemeral port.
- It calls `CreateThread()` for `win_stdin_thread_func()` before creating and connecting `socket_r`.
- `win_stdin_thread_func()` calls `accept()` on `tdata->socket_l` and accepts the first peer.
- No peer identity check, nonce, secret, or other authentication is performed before using the accepted socket.
- The thread then reads from `tdata->stdin_handle` with `ReadFile()` and writes those bytes to the accepted socket using `swrite()`.

A local attacker process on the same Windows host can race the intended self-connect, connect first to the loopback listener, and become `socket_w`. Once accepted, the attacker-controlled socket receives stdin bytes from the victim curl process.

## Why This Is A Real Bug

Binding to loopback limits exposure to the local host, but it does not authenticate the peer. Local processes of different privilege levels can connect to loopback sockets. Because the code accepts exactly the first connection and then streams stdin into it, the race winner controls the sink for potentially sensitive stdin data such as uploaded secrets, tokens, request bodies, or piped file contents.

The parent process intentionally creates its own socket only after the thread is started, so the race window is concrete and reachable by design rather than theoretical.

## Fix Requirement

Authenticate the intended self-connection before forwarding stdin, or replace the loopback TCP bridge with a non-network primitive such as a pipe or socketpair-equivalent mechanism that is not reachable by unrelated local processes.

## Patch Rationale

The patch adds a per-instance 16-byte random authentication token generated with `BCryptGenRandom()` before the thread starts. The token is stored in `tdata->auth` and copied locally for the parent.

After `accept()`, the thread reads exactly the token length from the accepted socket with a short receive timeout and compares it to `tdata->auth`. If the token is missing, incomplete, or incorrect, the thread closes the connection and exits without reading or forwarding stdin.

The parent sends the token on `socket_r` immediately after connecting and before shutting down writes. Only a peer that knows the freshly generated token can pass the authentication gate and receive stdin data.

This preserves the existing loopback bridge design while preventing unauthenticated local processes from becoming the stdin receiver.

## Residual Risk

None

## Patch

```diff
diff --git a/src/tool_doswin.c b/src/tool_doswin.c
index 4b2a2a34b3..bb7c6b4196 100644
--- a/src/tool_doswin.c
+++ b/src/tool_doswin.c
@@ -700,6 +700,10 @@ static void init_terminal(void)
 }
 
 #ifdef USE_WINSOCK
+#  include <bcrypt.h>
+#  ifndef STATUS_SUCCESS
+#    define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
+#  endif
 /* The following STDIN non - blocking read techniques are heavily inspired
    by nmap and ncat (https://nmap.org/ncat/) */
 struct win_thread_data {
@@ -709,11 +713,13 @@ struct win_thread_data {
   /* This is the listen socket for the thread. It is closed after the first
      connection. */
   curl_socket_t socket_l;
+  unsigned char auth[16];
 };
 
 static DWORD WINAPI win_stdin_thread_func(void *thread_data)
 {
   struct win_thread_data *tdata = (struct win_thread_data *)thread_data;
+  DWORD recvtimeout = 1000;
   struct sockaddr_in clientAddr;
   int clientAddrLen = sizeof(clientAddr);
 
@@ -728,6 +734,23 @@ static DWORD WINAPI win_stdin_thread_func(void *thread_data)
 
   sclose(tdata->socket_l);
   tdata->socket_l = CURL_SOCKET_BAD;
+  setsockopt(socket_w, SOL_SOCKET, SO_RCVTIMEO, (const char *)&recvtimeout,
+             sizeof(recvtimeout));
+  {
+    unsigned char auth[sizeof(tdata->auth)];
+    unsigned char *p = auth;
+    size_t nread = 0;
+
+    while(nread < sizeof(auth)) {
+      ssize_t n = sread(socket_w, (char *)p, sizeof(auth) - nread);
+      if(n <= 0)
+        goto ThreadCleanup;
+      nread += n;
+      p += n;
+    }
+    if(memcmp(auth, tdata->auth, sizeof(auth)))
+      goto ThreadCleanup;
+  }
   if(shutdown(socket_w, SHUT_RD)) {
     errorf("shutdown error: %d", SOCKERRNO);
     goto ThreadCleanup;
@@ -766,6 +789,7 @@ curl_socket_t win32_stdin_read_thread(void)
 {
   int rc = 0;
   struct win_thread_data *tdata = NULL;
+  unsigned char auth[16];
   static HANDLE stdin_thread = NULL;
   static curl_socket_t socket_r = CURL_SOCKET_BAD;
 
@@ -815,6 +839,13 @@ curl_socket_t win32_stdin_read_thread(void)
       break;
     }
 
+    if(BCryptGenRandom(NULL, tdata->auth, (ULONG)sizeof(tdata->auth),
+                       BCRYPT_USE_SYSTEM_PREFERRED_RNG) != STATUS_SUCCESS) {
+      errorf("BCryptGenRandom error");
+      break;
+    }
+    memcpy(auth, tdata->auth, sizeof(auth));
+
     /* Make a copy of the stdin handle to be used by win_stdin_thread_func */
     if(!DuplicateHandle(GetCurrentProcess(), GetStdHandle(STD_INPUT_HANDLE),
                         GetCurrentProcess(), &tdata->stdin_handle,
@@ -850,6 +881,23 @@ curl_socket_t win32_stdin_read_thread(void)
       break;
     }
 
+    {
+      unsigned char *p = auth;
+      size_t nleft = sizeof(auth);
+
+      while(nleft) {
+        ssize_t n = swrite(socket_r, (const char *)p, nleft);
+        if(n <= 0) {
+          errorf("send error: %d", SOCKERRNO);
+          break;
+        }
+        nleft -= n;
+        p += n;
+      }
+      if(nleft)
+        break;
+    }
+
     if(shutdown(socket_r, SHUT_WR)) {
       errorf("shutdown error: %d", SOCKERRNO);
       break;
```