# Unsynchronized Thread Handle Close

## Classification

Race condition, medium severity. Confidence: certain.

## Affected Locations

`server/mpm/winnt/nt_eventlog.c:109`

## Summary

`stderr_thread` is a global Win32 thread handle shared by `service_stderr_thread()` and `mpm_nt_eventlog_stderr_flush()` without synchronization. During stderr flush, the flushing thread can wait on and close a copied thread handle while the service stderr thread concurrently closes the same global handle and sets it to `NULL`. This creates an unsafe handle lifetime race.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

`service_stderr_thread()` exits while another thread calls `mpm_nt_eventlog_stderr_flush()`.

## Proof

`stderr_thread` is initialized globally in `mpm_nt_eventlog_stderr_open()` by `CreateThread()`.

Before the patch:

- `mpm_nt_eventlog_stderr_flush()` copied `stderr_thread` into `cleanup_thread`.
- It then closed stderr, closed the stderr handle, waited on `cleanup_thread`, and finally called `CloseHandle(cleanup_thread)`.
- Closing stderr is the normal trigger that lets `service_stderr_thread()` leave its `ReadFile()` loop.
- On exit, `service_stderr_thread()` also called `CloseHandle(stderr_thread)` and set `stderr_thread = NULL`.

Therefore, the flush path could copy the handle and then race with the service thread closing the same handle before or during `WaitForSingleObject(cleanup_thread, 30000)`. The copied value could become invalid, or worse, refer to a reused unrelated handle by the time it is waited on or closed.

## Why This Is A Real Bug

Win32 handle lifetime rules do not allow one thread to close a handle while another thread may concurrently wait on or close that same handle value. The previous code had two unsynchronized owners for `stderr_thread`.

The race is practical during ordinary shutdown/log-drain behavior: `mpm_nt_eventlog_stderr_flush()` closes stderr, which causes `service_stderr_thread()` to exit and execute its own close of `stderr_thread`. This can produce unreliable shutdown behavior and, if the handle value is reused, can cause the stale `CloseHandle(cleanup_thread)` to close an unrelated process handle.

## Fix Requirement

Make only one code path own and close `stderr_thread`, and ensure the global handle is claimed atomically before cleanup.

## Patch Rationale

The patch removes the `CloseHandle(stderr_thread)` and `stderr_thread = NULL` operations from `service_stderr_thread()`, leaving handle cleanup to `mpm_nt_eventlog_stderr_flush()`.

`mpm_nt_eventlog_stderr_flush()` now claims ownership with:

```c
HANDLE cleanup_thread = InterlockedExchangePointer((PVOID volatile *)&stderr_thread,
                                                   NULL);
```

This atomically exchanges the global handle with `NULL`, ensuring only the caller that receives the non-`NULL` handle owns the wait and close sequence. The service thread no longer closes the thread handle behind the flushing thread, eliminating the unsynchronized close/wait race.

## Residual Risk

None

## Patch

```diff
diff --git a/server/mpm/winnt/nt_eventlog.c b/server/mpm/winnt/nt_eventlog.c
index cd49ee6..5b9ce70 100644
--- a/server/mpm/winnt/nt_eventlog.c
+++ b/server/mpm/winnt/nt_eventlog.c
@@ -109,8 +109,6 @@ static DWORD WINAPI service_stderr_thread(LPVOID hPipe)
 
     CloseHandle(hPipeRead);
     DeregisterEventSource(hEventSource);
-    CloseHandle(stderr_thread);
-    stderr_thread = NULL;
     apr_pool_destroy(p);
     return 0;
 }
@@ -118,7 +116,8 @@ static DWORD WINAPI service_stderr_thread(LPVOID hPipe)
 
 void mpm_nt_eventlog_stderr_flush(void)
 {
-    HANDLE cleanup_thread = stderr_thread;
+    HANDLE cleanup_thread = InterlockedExchangePointer((PVOID volatile *)&stderr_thread,
+                                                       NULL);
 
     if (cleanup_thread) {
         HANDLE hErr = GetStdHandle(STD_ERROR_HANDLE);
```