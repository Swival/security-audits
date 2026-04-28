# Racy MaxConnectionsPerChild Counter

## Classification

Race condition, medium severity, confidence certain.

## Affected Locations

`server/mpm/winnt/child.c:821`

## Summary

The Windows MPM worker threads share a static `requests_this_child` counter inside `worker_main()`. The counter is incremented with a non-atomic `requests_this_child++` and then compared against `ap_max_requests_per_child`. Because multiple worker threads execute `worker_main()` concurrently, increments can be lost, causing the child process to undercount handled connections and delay or miss the configured `MaxConnectionsPerChild` recycle.

## Provenance

Identified by Swival Security Scanner: https://swival.dev

## Preconditions

- Multiple worker threads handle connections concurrently.
- `MaxConnectionsPerChild` / `ap_max_requests_per_child` is nonzero.

## Proof

Worker threads are created by `CreateThread()` for `ap_threads_per_child` workers, all entering `worker_main()` concurrently.

In `worker_main()`, `requests_this_child` is a static local variable shared by all worker threads. The original code performs:

```c
requests_this_child++;
if (requests_this_child > ap_max_requests_per_child) {
    SetEvent(max_requests_per_child_event);
}
```

The increment is a read-modify-write without a mutex or atomic operation. Two workers can both read `0`, both compute `1`, and both store `1`. With `ap_max_requests_per_child == 1`, both compare `1 > 1`, which is false, so neither signals `max_requests_per_child_event`.

That event is waited on by `child_main()`. When signaled, `child_main()` logs that `MaxConnectionsPerChild` was reached and calls `ap_signal_parent(SIGNAL_PARENT_RESTART)`. Lost increments therefore directly prevent or delay the configured restart path.

## Why This Is A Real Bug

This is a source-grounded race on shared mutable state. The counter controls a lifecycle policy: when the child has handled the configured number of connections, it should notify the parent to recycle the process. Lost updates let the process handle more connections than configured. For finite traffic bursts, the recycle can be missed entirely.

## Fix Requirement

Make the counter update atomic or protect the counter with a mutex, and compare using the value returned by the synchronized increment.

## Patch Rationale

The patch changes `requests_this_child` from `int` to `apr_uint32_t` and replaces the unsynchronized post-increment with `apr_atomic_inc32()`:

```c
if (apr_atomic_inc32(&requests_this_child) >= ap_max_requests_per_child) {
    SetEvent(max_requests_per_child_event);
}
```

`apr_atomic_inc32()` performs the shared counter increment atomically across worker threads and returns the incremented value used for the threshold comparison. This removes the lost-update race without adding a new lock on the connection hot path.

The comparison uses `>=` because the atomic increment returns the new count. This preserves the intended policy of signaling once the configured connection count is reached, rather than relying on a racy post-increment and separate read.

## Residual Risk

None

## Patch

```diff
diff --git a/server/mpm/winnt/child.c b/server/mpm/winnt/child.c
index 05151a8..78977c5 100644
--- a/server/mpm/winnt/child.c
+++ b/server/mpm/winnt/child.c
@@ -786,7 +786,7 @@ static DWORD __stdcall worker_main(void *thread_num_val)
 {
     apr_thread_t *thd = NULL;
     apr_os_thread_t osthd = NULL;
-    static int requests_this_child = 0;
+    static apr_uint32_t requests_this_child = 0;
     winnt_conn_ctx_t *context = NULL;
     int thread_num = (int)thread_num_val;
     ap_sb_handle_t *sbh;
@@ -818,8 +818,7 @@ static DWORD __stdcall worker_main(void *thread_num_val)
 
         /* Have we hit MaxConnectionsPerChild connections? */
         if (ap_max_requests_per_child) {
-            requests_this_child++;
-            if (requests_this_child > ap_max_requests_per_child) {
+            if (apr_atomic_inc32(&requests_this_child) >= ap_max_requests_per_child) {
                 SetEvent(max_requests_per_child_event);
             }
         }
```