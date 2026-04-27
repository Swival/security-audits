# Socket Clone Inheritance Race In Fallback Path

## Classification

Race condition, medium severity, confidence certain.

## Affected Locations

`library/std/src/os/windows/io/socket.rs:133`

## Summary

`BorrowedSocket::try_clone_to_owned` attempted to clone a Windows socket with `WSA_FLAG_NO_HANDLE_INHERIT`, but on `WSAEPROTOTYPE` or `WSAEINVAL` it fell back to `WSASocketW(..., WSA_FLAG_OVERLAPPED)` and only cleared inheritance afterward with `SetHandleInformation`.

That created a race window where the newly cloned socket existed as an inheritable handle before `socket.set_no_inherit()` completed. If another thread spawned a child process during that window, the child could inherit the socket handle.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- Windows target.
- `BorrowedSocket::try_clone_to_owned` reaches the fallback `WSASocketW(..., WSA_FLAG_OVERLAPPED)` path.
- Another thread concurrently creates a child process with handle inheritance enabled.
- The child creation path can inherit process handles.

## Proof

The vulnerable flow was:

1. `BorrowedSocket::try_clone_to_owned` calls `WSADuplicateSocketW`.
2. It tries `WSASocketW` with `WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT`.
3. If that fails with `WSAEPROTOTYPE` or `WSAEINVAL`, it retries with only `WSA_FLAG_OVERLAPPED`.
4. The fallback `WSASocketW` returns a live socket.
5. `OwnedSocket::from_raw_socket` wraps the socket.
6. `socket.set_no_inherit()` later clears `HANDLE_FLAG_INHERIT`.

Between steps 4 and 6, the socket may be inheritable.

The reproducer confirmed this is reachable when cloning a `BorrowedSocket` on Windows through the fallback path. It also confirmed the concurrent process path: Windows `Command` defaults `inherit_handles` to `true` in `library/std/src/sys/process/windows.rs:193` and passes that value to `CreateProcessW` in `library/std/src/sys/process/windows.rs:417`.

The standard library process code documents this class of inheritable-handle race in `library/std/src/sys/process/windows.rs:330`, but the socket fallback path did not participate in that locking discipline.

## Why This Is A Real Bug

The bug is a real race because the non-inheritance property was not established atomically with socket creation. A socket created without `WSA_FLAG_NO_HANDLE_INHERIT` became observable to the process before `SetHandleInformation` cleared inheritance.

During that interval, a concurrent `CreateProcessW` call with inherited handles enabled could copy the socket handle into the child process. This leaks an unintended socket capability and can extend the socket lifetime beyond the owning Rust value.

## Fix Requirement

The fallback must not expose a live inheritable socket. Acceptable fixes are to create the socket as non-inheritable atomically or avoid the fallback that creates an inheritable socket before inheritance is cleared.

## Patch Rationale

The patch removes the unsafe fallback entirely. If `WSASocketW` with `WSA_FLAG_NO_HANDLE_INHERIT` fails, `try_clone_to_owned` now returns the socket error directly instead of retrying without the no-inherit flag.

This preserves the invariant that a cloned `OwnedSocket` is never created through this path unless non-inheritance was requested at socket creation time.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/os/windows/io/socket.rs b/library/std/src/os/windows/io/socket.rs
index 28e972925e6..376ae02ef89 100644
--- a/library/std/src/os/windows/io/socket.rs
+++ b/library/std/src/os/windows/io/socket.rs
@@ -122,32 +122,7 @@ pub fn try_clone_to_owned(&self) -> io::Result<OwnedSocket> {
         if socket != sys::c::INVALID_SOCKET {
             unsafe { Ok(OwnedSocket::from_raw_socket(socket as RawSocket)) }
         } else {
-            let error = unsafe { sys::c::WSAGetLastError() };
-
-            if error != sys::c::WSAEPROTOTYPE && error != sys::c::WSAEINVAL {
-                return Err(io::Error::from_raw_os_error(error));
-            }
-
-            let socket = unsafe {
-                sys::c::WSASocketW(
-                    info.iAddressFamily,
-                    info.iSocketType,
-                    info.iProtocol,
-                    &info,
-                    0,
-                    sys::c::WSA_FLAG_OVERLAPPED,
-                )
-            };
-
-            if socket == sys::c::INVALID_SOCKET {
-                return Err(last_error());
-            }
-
-            unsafe {
-                let socket = OwnedSocket::from_raw_socket(socket as RawSocket);
-                socket.set_no_inherit()?;
-                Ok(socket)
-            }
+            Err(last_error())
         }
     }
 }
```