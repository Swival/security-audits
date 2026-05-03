# Fragmented SockJS WebSocket Frames Accumulate Without Total Cap

## Classification

Denial of service, high severity, certain confidence.

## Affected Locations

`src/proxy/sockjssession.cpp:655`

## Summary

`SockJsSession` in `WebSocketFramed` mode capped only individual wrapped WebSocket frame fragments before appending them to `inWrappedFrames`. The cumulative wrapped payload size was checked only after a terminating fragment was present. A remote client could continuously send non-final fragments, keeping the SockJS message incomplete while causing unbounded growth of `inWrappedFrames` and proxy worker memory exhaustion.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- `SockJsSession` runs in `WebSocketFramed` mode for the attacker-controlled connection.
- The attacker can send WebSocket frames for the framed SockJS transport.
- The attacker sends continuous non-final fragments with `more` set.
- Each fragment remains below the existing per-frame limit.

## Proof

In `WebSocketFramed` `tryRead`, the read loop runs while `inBytes < BUFFER_SIZE`.

When no complete wrapped message exists, the code searches `inWrappedFrames` for a fragment where `more` is false. If none exists, it reads another frame with `sock->readFrame()` and previously rejected only frames where `f.data.size() > BUFFER_SIZE * 2`.

That allowed this sequence:

1. Send many WebSocket frames with `more` set.
2. Keep each frame below `BUFFER_SIZE * 2`.
3. Never send a final fragment.
4. `inWrappedFrames += f` executes repeatedly.
5. `inBytes` remains unchanged because it is incremented only after a complete wrapped message is parsed.
6. The loop and future readiness events continue accepting fragments, growing memory without a cumulative cap.

The reproducer confirmed:

- Missing cap at `src/proxy/sockjssession.cpp:651`, `src/proxy/sockjssession.cpp:655`, and `src/proxy/sockjssession.cpp:663`.
- Only per-frame size was checked at `src/proxy/sockjssession.cpp:658`.
- The cumulative wrapped size check at `src/proxy/sockjssession.cpp:672` was reached only after a final fragment existed.
- `inBytes` was incremented only after parsed complete messages at `src/proxy/sockjssession.cpp:724`.
- `ZWebSocket::readFrame()` returned credits once drained into `inWrappedFrames` at `src/core/zwebsocket.cpp:268`, allowing continued streaming.

## Why This Is A Real Bug

The existing `inBytes < BUFFER_SIZE` guard does not limit incomplete wrapped SockJS data. `inBytes` tracks parsed application frames, not pending wrapped fragments. For permanently incomplete fragmented messages, `inBytes` stays below the limit while `inWrappedFrames` grows. Since flow-control credits are returned after `SockJsSession` drains frames from `ZWebSocket`, an attacker can sustain the condition over time and exhaust worker memory.

## Fix Requirement

Cap the total number of bytes stored in `inWrappedFrames`, including the newly read fragment, before appending it. If the cumulative incomplete wrapped size exceeds the temporary wrapping allowance, treat it as an error and close/cleanup the session.

## Patch Rationale

The patch computes the cumulative pending wrapped size before appending the newly read frame:

```cpp
int size = f.data.size();
for (const Frame &wrappedFrame : inWrappedFrames)
    size += wrappedFrame.data.size();
```

It then applies the existing `BUFFER_SIZE * 2` wrapped-message allowance to the cumulative size instead of the single incoming frame size:

```cpp
if (size > BUFFER_SIZE * 2) {
    error = true;
    break;
}
```

This preserves the intended larger temporary allowance for SockJS wrapping while preventing incomplete fragmented messages from accumulating without bound.

## Residual Risk

None

## Patch

```diff
diff --git a/src/proxy/sockjssession.cpp b/src/proxy/sockjssession.cpp
index 7438f0a0..36150ba3 100644
--- a/src/proxy/sockjssession.cpp
+++ b/src/proxy/sockjssession.cpp
@@ -654,8 +654,12 @@ public:
 
                     Frame f = sock->readFrame();
 
+                    int size = f.data.size();
+                    for (const Frame &wrappedFrame : inWrappedFrames)
+                        size += wrappedFrame.data.size();
+
                     // Allow a larger temporary read size due to wrapping
-                    if (f.data.size() > BUFFER_SIZE * 2) {
+                    if (size > BUFFER_SIZE * 2) {
                         error = true;
                         break;
                     }
```