# Telnet upload blocks past configured timeout

## Classification

Denial of service, medium severity, certain confidence.

## Affected Locations

`lib/telnet.c:650` (`send_telnet_data` writability poll)

## Summary

Telnet uploads call `Curl_poll()` with an infinite timeout while waiting for the socket to become writable. A peer that accepts the connection but stops reading can fill the kernel send buffer and pin the upload thread inside `send_telnet_data()` indefinitely. The outer transfer-timeout check in `telnet_do()` runs only after `send_telnet_data()` returns, so `CURLOPT_TIMEOUT` is effectively bypassed for telnet uploads against an unresponsive server.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

Verified from source review.

## Preconditions

- The client uploads data over telnet.
- `CURLOPT_TIMEOUT` is configured.
- The peer accepts the TCP connection but stops draining its receive window.
- The upload payload is large enough to fill the local send buffer.

## Proof

`send_telnet_data()` writes upload data in a loop. Before each `Curl_xfer_send()`, it waits for the socket to become writable:

```c
switch(Curl_poll(pfd, 1, -1)) {
case -1:                    /* error, abort writing */
case 0:                     /* timeout (will never happen) */
  result = CURLE_SEND_ERROR;
  break;
default:                    /* write! */
  ...
}
```

`Curl_poll()` treats a negative timeout as an indefinite wait, which matches the in-source comment `timeout (will never happen)`.

If the peer stops reading, the client kernel send buffer fills and the socket never becomes writable. The function therefore blocks indefinitely inside `Curl_poll()`.

The `CURLOPT_TIMEOUT` check sits in the outer `telnet_do()` loop at `lib/telnet.c:1547`, after `send_telnet_data()` returns. Because that loop only runs between calls, the timeout cannot be enforced while the inner poll is blocked.

## Why This Is A Real Bug

`CURLOPT_TIMEOUT` is documented as the upper bound on the entire transfer. The telnet upload path violates that contract by waiting forever on a socket-writability poll, allowing an attacker-controlled or unresponsive peer to pin the client thread regardless of the configured timeout.

This is a deterministic, attacker-triggerable denial of service against a thread or process whose lifetime is supposed to be bounded by the caller-configured timeout.

## Fix Requirement

The writability poll in `send_telnet_data()` must respect the remaining transfer time and return `CURLE_OPERATION_TIMEDOUT` when the configured timeout elapses.

## Patch Rationale

The patch computes the remaining transfer time with `Curl_timeleft_ms(data)` on each loop iteration and:

- Returns `CURLE_OPERATION_TIMEDOUT` if the budget has already expired.
- Passes the remaining time to `Curl_poll()` instead of `-1`. The previous behavior (infinite wait) is preserved when no timeout is configured (`Curl_timeleft_ms` returns `0`).
- Treats poll result `0` as `CURLE_OPERATION_TIMEDOUT` rather than the old fallthrough `CURLE_SEND_ERROR`.

This makes the configured transfer timeout reachable from inside the upload path without changing default behavior when no timeout is configured.

## Residual Risk

When no `CURLOPT_TIMEOUT` is configured the writability poll still has no cap. Callers relying on the default for telnet uploads to potentially unresponsive servers remain exposed to long hangs. Configuring a timeout is now sufficient to bound the operation.

## Patch

```diff
diff --git a/lib/telnet.c b/lib/telnet.c
index c5ce9c2c97..f395753c88 100644
--- a/lib/telnet.c
+++ b/lib/telnet.c
@@ -49,6 +49,7 @@
 
 #include "url.h"
 #include "transfer.h"
+#include "connect.h"
 #include "sendf.h"
 #include "curl_trc.h"
 #include "progress.h"
@@ -643,15 +644,22 @@ static CURLcode send_telnet_data(struct Curl_easy *data,
     outbuf = (const unsigned char *)buffer;
   }
   while(!result && total_written < outlen) {
+    timediff_t timeout_ms = Curl_timeleft_ms(data);
     /* Make sure socket is writable to avoid EWOULDBLOCK condition */
     struct pollfd pfd[1];
     pfd[0].fd = conn->sock[FIRSTSOCKET];
     pfd[0].events = POLLOUT;
-    switch(Curl_poll(pfd, 1, -1)) {
+    if(timeout_ms < 0) {
+      result = CURLE_OPERATION_TIMEDOUT;
+      break;
+    }
+    switch(Curl_poll(pfd, 1, timeout_ms ? timeout_ms : -1)) {
     case -1:                    /* error, abort writing */
-    case 0:                     /* timeout (will never happen) */
       result = CURLE_SEND_ERROR;
       break;
+    case 0:                     /* timeout */
+      result = CURLE_OPERATION_TIMEDOUT;
+      break;
     default:                    /* write! */
       bytes_written = 0;
       result = Curl_xfer_send(data, outbuf + total_written,
```
