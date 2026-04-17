# Worker cleanup double-closes the cache-manager thread handle

## Classification
- Type: resource lifecycle bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `src/os/win32/ngx_process_cycle.c:581`
- `src/os/win32/ngx_process_cycle.c:750`
- `src/os/win32/ngx_process_cycle.c:751`
- `src/os/win32/ngx_process_cycle.c:1038`

## Summary
During Win32 worker shutdown, `ngx_worker_process_cycle` repacks its wait array after `wtid` exits first by copying `events[2]` into `events[1]` and shrinking `nev` to 2. The removed slot is not cleared. Cleanup later unconditionally closes both `events[1]` and `events[2]`, causing the same `cmtid` handle to be passed to `CloseHandle()` twice.

## Provenance
- Verified from local reproduction against `src/os/win32/ngx_process_cycle.c`
- Swival Security Scanner: https://swival.dev

## Preconditions
- Worker shutdown reaches the thread-wait cleanup path
- `WaitForMultipleObjects()` returns `WAIT_OBJECT_0 + 1`, meaning `wtid` exits before `cmtid`

## Proof
- Shutdown assigns `events[1] = wtid`, `events[2] = cmtid`, `nev = 3` in `ngx_worker_process_cycle`.
- On `WAIT_OBJECT_0 + 1`, the code executes `events[1] = events[2]; nev = 2;`, removing `wtid` from the active wait set.
- That branch does not clear `events[2]`, so both `events[1]` and `events[2]` now hold `cmtid`.
- Cleanup unconditionally calls `ngx_close_handle(events[1])` and `ngx_close_handle(events[2])` at `src/os/win32/ngx_process_cycle.c:750` and `src/os/win32/ngx_process_cycle.c:751`.
- `ngx_close_handle()` is a thin wrapper around `CloseHandle(h)` with logging at `src/os/win32/ngx_process_cycle.c:1038`.
- The second close therefore operates on an already-closed thread handle and fails with `ERROR_INVALID_HANDLE`.

## Why This Is A Real Bug
The reproduced path is reachable whenever the worker thread terminates before the cache-manager thread during shutdown. On that path, the code deterministically aliases `events[1]` and `events[2]` to the same handle and then closes both. This is not speculative stale-state handling; it is a concrete duplicate `CloseHandle()` on the same Win32 thread handle, producing invalid-handle failure during normal shutdown.

## Fix Requirement
Track the owned thread handles independently from the mutable wait-array contents, and only close each live handle once after the wait set shrinks.

## Patch Rationale
The patch separates cleanup ownership from `events[]` bookkeeping so wait-array compaction cannot create aliasing-driven double closes. This preserves shutdown behavior while ensuring `wtid` and `cmtid` are each closed at most once, regardless of which thread exits first.

## Residual Risk
None

## Patch
- Patch file: `010-worker-cleanup-closes-an-invalid-thread-handle.patch`
- The fix updates `src/os/win32/ngx_process_cycle.c` to keep distinct thread-handle variables for cleanup and stops using the compacted `events[]` slots as the source of truth for `CloseHandle()` decisions.