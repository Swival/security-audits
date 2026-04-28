# Unbounded HTTP/2 Priority Recursion

## Classification

Vulnerability, medium severity. Confidence: certain.

## Affected Locations

`modules/http2/h2_session.c:176`

## Summary

`stream_pri_cmp()` compares HTTP/2 stream priority by calling `spri_cmp()`. The original `spri_cmp()` recursively walks parent streams with `nghttp2_stream_get_parent()` and has no depth limit. A client can send PRIORITY frames that create a deep dependency chain, then trigger reprioritization, causing recursion proportional to the client-controlled priority-tree depth. This can exhaust the C stack and crash the worker/session.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

## Preconditions

- A client can send HTTP/2 PRIORITY frames.
- The client can create a deep HTTP/2 dependency chain.
- Streams remain queued so reprioritization compares queued stream priorities.
- `H2MaxSessionStreams` is configured high enough to permit a sufficiently deep chain.

## Proof

- `modules/http2/h2_session.c:414` accepts `NGHTTP2_PRIORITY` frames and sets `session->reprioritize = 1`.
- `modules/http2/h2_session.c:1941` processes that flag by calling `h2_mplx_c1_reprioritize(session->mplx, stream_pri_cmp, session)`.
- `modules/http2/h2_mplx.c:679` sorts the pending stream queue with the supplied comparator.
- `modules/http2/h2_session.c:197` calls `spri_cmp()` from `stream_pri_cmp()`.
- The original `spri_cmp()` recursively calls itself after following `nghttp2_stream_get_parent()` for both streams.
- There is no local recursion depth limit in the original comparator.
- `modules/http2/h2_config.c:590` only requires `H2MaxSessionStreams > 0` and applies no upper bound.

A client can therefore open many streams, arrange them into a deep priority dependency chain with PRIORITY frames, and trigger reprioritization while streams are queued in `m->q`. Comparisons recurse once per shared dependency-tree level, allowing stack exhaustion.

## Why This Is A Real Bug

The recursion depth is derived from client-controlled HTTP/2 priority state, not from a fixed server-side bound. Reprioritization invokes the comparator during queue sorting, so a single deep tree can cause many comparator calls. In the vulnerable implementation, each comparison can consume stack frames proportional to dependency-tree depth. With a sufficiently deep configured stream limit, this is a reliable denial-of-service condition against the affected worker/session.

## Fix Requirement

Replace recursive parent traversal with an iterative implementation that has a bounded maximum walk depth, or reject/cap accepted priority-tree depth before reprioritization.

## Patch Rationale

The patch converts `spri_cmp()` from recursion to a loop and caps the walk at 1000 parent levels. This removes unbounded stack growth because parent traversal no longer consumes one C stack frame per priority-tree level. If the cap is reached before a priority relationship is resolved, the comparator falls back to deterministic stream-id ordering with `sid1 - sid2`, preserving a stable ordering without continuing attacker-controlled traversal.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/http2/h2_session.c b/modules/http2/h2_session.c
index 21ede5c..a76e540 100644
--- a/modules/http2/h2_session.c
+++ b/modules/http2/h2_session.c
@@ -155,26 +155,32 @@ static int spri_cmp(int sid1, nghttp2_stream *s1,
                     int sid2, nghttp2_stream *s2, h2_session *session)
 {
     nghttp2_stream *p1, *p2;
+    int depth = 0;
     
-    p1 = nghttp2_stream_get_parent(s1);
-    p2 = nghttp2_stream_get_parent(s2);
-    
-    if (p1 == p2) {
-        int32_t w1, w2;
+    (void)session;
+    while (depth++ < 1000) {
+        p1 = nghttp2_stream_get_parent(s1);
+        p2 = nghttp2_stream_get_parent(s2);
         
-        w1 = nghttp2_stream_get_weight(s1);
-        w2 = nghttp2_stream_get_weight(s2);
-        return w2 - w1;
+        if (p1 == p2) {
+            int32_t w1, w2;
+            
+            w1 = nghttp2_stream_get_weight(s1);
+            w2 = nghttp2_stream_get_weight(s2);
+            return w2 - w1;
+        }
+        else if (!p1) {
+            /* stream 1 closer to root */
+            return -1;
+        }
+        else if (!p2) {
+            /* stream 2 closer to root */
+            return 1;
+        }
+        s1 = p1;
+        s2 = p2;
     }
-    else if (!p1) {
-        /* stream 1 closer to root */
-        return -1;
-    }
-    else if (!p2) {
-        /* stream 2 closer to root */
-        return 1;
-    }
-    return spri_cmp(sid1, p1, sid2, p2, session);
+    return sid1 - sid2;
 }
 
 static int stream_pri_cmp(int sid1, int sid2, void *ctx)
```