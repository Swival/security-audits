# Listener Thread Handle Leak

## Classification

Resource lifecycle bug; severity: low; confidence: certain.

## Affected Locations

`server/mpm/winnt/child.c:913`

## Summary

`create_listener_thread()` starts one Windows listener thread per active listener socket using `_beginthreadex()`, but the returned thread handle is discarded. On Windows, a thread object handle returned by `_beginthreadex()` must be closed when the caller does not need to wait on it. The leak is bounded to one handle per listener thread per child process lifetime.

## Provenance

Found by Swival Security Scanner: https://swival.dev

## Preconditions

- The child process starts at least one listener thread.
- At least one `ap_listeners` entry has a non-NULL `lr->sd`.

## Proof

`create_listener_thread()` walks `ap_listeners` and starts a listener/accept thread for every listener with non-NULL `lr->sd`.

The leaking operation is the `_beginthreadex(...)` call in `server/mpm/winnt/child.c`, where the returned thread handle is ignored. The adjacent comment states that a returned handle “cannot be ignored” and “must be closed/joined.”

Shutdown handling only tracks worker thread handles in `child_handles`. Those worker handles are waited on and closed through `cleanup_thread()` and the remaining-thread cleanup loop. Listener thread handles are not added to `child_handles`, stored elsewhere, waited on, or closed.

Therefore, each successfully created listener thread leaves its Windows thread handle open until process exit.

## Why This Is A Real Bug

`_beginthreadex()` returns a Windows thread handle owned by the caller. Even after the thread exits, the kernel thread object remains referenced until all open handles to it are closed. Because the code discards the handle, the process loses the only reference needed to close it.

The listener thread itself can exit during shutdown, but the leaked handle cannot be closed afterward because it was never retained. This produces a bounded handle leak of one handle per listener socket per child process.

## Fix Requirement

Store the `_beginthreadex()` return value and close it when the caller does not need to join the listener thread.

## Patch Rationale

The patch captures the returned `_beginthreadex()` handle and immediately calls `CloseHandle()` when thread creation succeeds.

This is correct because the existing lifecycle does not join listener threads by handle. Closing the handle does not terminate the thread; it only releases the caller’s kernel object reference. The listener thread continues to run normally and exits through the existing shutdown path.

## Residual Risk

None

## Patch

```diff
diff --git a/server/mpm/winnt/child.c b/server/mpm/winnt/child.c
index 05151a8..3aa09a8 100644
--- a/server/mpm/winnt/child.c
+++ b/server/mpm/winnt/child.c
@@ -910,8 +910,14 @@ static void create_listener_thread(void)
              * To convert to CreateThread, the returned handle cannot be
              * ignored, it must be closed/joined.
              */
-            _beginthreadex(NULL, 65536, winnt_accept,
-                           (void *) lr, stack_res_flag, &tid);
+            HANDLE thread_handle = (HANDLE)_beginthreadex(NULL, 65536,
+                                                          winnt_accept,
+                                                          (void *) lr,
+                                                          stack_res_flag,
+                                                          &tid);
+            if (thread_handle) {
+                CloseHandle(thread_handle);
+            }
         }
     }
 }
```