# Wrong pending event sentinel blocks new connections

## Classification
- Type: invariant violation
- Severity: high
- Confidence: certain

## Affected Locations
- `src/event/ngx_event_connectex.c:116`
- `src/event/ngx_event_connectex.c:158`
- `src/event/ngx_event_connectex.c:167`

## Summary
`ngx_iocp_wait_events()` uses slot 0 as a sentinel for pending outbound connects by setting `conn[0] = NULL` and `events[0] = pending_connect_event`. The dispatch logic later checks `if (events[n] == NULL)` instead of the sentinel-bearing connection slot. As a result, a wakeup on slot 0 never enters the pending-connect branch and queued connects are not dequeued via `ngx_iocp_new_connect()`.

## Provenance
- Verified finding reproduced from the provided report and reproducer notes
- Reference scanner: https://swival.dev

## Preconditions
- A pending connect event is signaled while the worker thread is waiting for events

## Proof
- The wait setup assigns the sentinel to the connection array: `conn[0] = NULL`, while slot 0 still has a non-NULL event handle in `events[0] = pending_connect_event`.
- The dispatcher tests the wrong array at `src/event/ngx_event_connectex.c:116` with `if (events[n] == NULL)`.
- Because `events[0]` is the pending-connect event handle, the condition is false for the wakeup intended to service queued connects.
- The code therefore skips the branch at `src/event/ngx_event_connectex.c:158` that calls `ngx_iocp_new_connect()`.
- The fallback path then treats slot 0 as a normal socket event at `src/event/ngx_event_connectex.c:167`, despite `conn[0]` being the NULL sentinel, so the queued connect remains in `pending_connects[]` and the wakeup is lost.

## Why This Is A Real Bug
The implementation relies on a slot-0 sentinel invariant: pending-connect wakeups are identified by a NULL connection pointer, not by a NULL event handle. Testing `events[n]` breaks that invariant deterministically because the pending-connect slot is intentionally backed by a valid event object. This prevents the only dequeue path for queued outbound connects from running, causing connection setup to stall on Windows IOCP.

## Fix Requirement
Dispatch the pending-connect wakeup using the actual sentinel source. The check must use `conn[n] == NULL` or an equivalent comparison against `pending_connect_event`, so slot 0 reliably reaches `ngx_iocp_new_connect()`.

## Patch Rationale
The patch changes the branch condition to test the sentinel-bearing connection slot instead of the event handle. This restores the intended invariant, ensures slot 0 wakeups enter the pending-connect path, and allows queued outbound connects to be dequeued and registered correctly.

## Residual Risk
None

## Patch
- Patch file: `014-wrong-pending-event-sentinel-blocks-new-connections.patch`
- Change: replace the pending-connect dispatch check in `src/event/ngx_event_connectex.c:116` so it keys on `conn[n] == NULL` rather than `events[n] == NULL`
- Effect: pending-connect wakeups now correctly call `ngx_iocp_new_connect()` and no longer fall through as normal socket events