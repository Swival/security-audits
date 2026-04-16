# Pending requests dropped during reconnect

## Classification
- Type: race condition
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/common/memcached.c:280`
- `lib/common/memcached.c:120`
- `lib/common/memcached.c:125`
- `src/ssl.c:955`
- `lib/core/util.c:138`

## Summary
`dispatch` drops requests whenever `ctx->num_threads_connected == 0` at `lib/common/memcached.c:280`. During a transient memcached disconnect, the last reader thread decrements that counter to zero before reconnecting, creating a window where new requests are discarded instead of queued. In the default single-thread configuration, this is directly reachable on any temporary disconnect and causes silent request loss.

## Provenance
- Verified from source review and reproducer-backed analysis supplied with this finding
- Scanner provenance: https://swival.dev

## Preconditions
- All memcached reader threads are currently disconnected
- A request reaches `h2o_memcached_get`, `h2o_memcached_set`, or `h2o_memcached_delete` during the reconnect window before any replacement reader increments `ctx->num_threads_connected`

## Proof
- `h2o_memcached_get`, `h2o_memcached_set`, and `h2o_memcached_delete` call `dispatch`
- `dispatch` checks `ctx->num_threads_connected == 0` and routes requests to `discard_req` at `lib/common/memcached.c:280`
- After a reader-side failure, the reader thread decrements the connected count and only discards pending queue contents when transitioning to zero, then immediately loops to reconnect
- The replacement reader increments the connected count only after reconnect setup completes, so requests arriving in that interval are dropped rather than retained
- In the default configuration, `cache-memcached-num-threads = 1` at `src/ssl.c:955`, so any temporary disconnect of the sole reader opens this window
- Dropped `get` requests complete through `discard_req` at `lib/common/memcached.c:120`; the SSL resumption path treats the resulting null response as a cache miss at `lib/core/util.c:138`, causing silent fallback to full handshake
- Dropped `set` and `delete` requests are freed at `lib/common/memcached.c:125`, silently losing writes

## Why This Is A Real Bug
This is not a theoretical queueing preference; it changes externally observable behavior. Temporary backend disconnects cause in-flight API calls to be reported as cache misses or ignored writes, even though the subsystem is actively reconnecting and the context remains live. The effect is silent state loss. In the common single-thread deployment, the race is practical and deterministic whenever the sole memcached connection drops.

## Fix Requirement
Requests must be queued regardless of temporary connection state. They may be discarded only when the memcached context is being torn down, not merely because all workers are momentarily disconnected during reconnect.

## Patch Rationale
The patch removes the reconnect-window drop behavior from normal dispatch so requests continue to accumulate while workers re-establish connectivity. Discard logic is preserved for actual context teardown, matching the intended reliability boundary: temporary disconnects delay processing, while shutdown still terminates pending work explicitly.

## Residual Risk
None

## Patch
- Patch file: `019-pending-requests-are-dropped-during-reconnect-window.patch`
- Intended change: update `lib/common/memcached.c` so `dispatch` enqueues unconditionally during reconnect periods and pending requests are only discarded during teardown