# Dispose races leased socket close callback

## Classification
- Type: resource lifecycle bug
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/common/socketpool.c:183`
- `lib/common/socketpool.c:396`
- `lib/common/socketpool.c:584`
- `lib/common/socketpool.c:620`
- `lib/common/socket.c:521`
- `lib/common/socket.c:524`
- `lib/common/socket.c:526`

## Summary
`h2o_socketpool_dispose` frees `pool->targets.entries` while leased sockets can still retain `on_close` handlers whose callback state points back to the pool and later dereferences `pool->targets.entries[close_data->target]`. If such a socket closes after disposal, `on_close` executes on freed target storage and triggers a use-after-free.

## Provenance
- Reproduced from the verified finding and trace evidence supplied by the user
- Scanner: https://swival.dev
- Patched in `011-dispose-frees-pool-targets-before-async-close-callback-runs.patch`

## Preconditions
- `dispose` runs while a leased socket still has `on_close` installed

## Proof
`start_connect` and pooled-socket reuse install `on_close` state that stores the owning `pool` and target index. Later, `on_close` dereferences `pool->targets.entries[close_data->target]` at `lib/common/socketpool.c:396`.

`h2o_socketpool_dispose` frees target storage at `lib/common/socketpool.c:183` without clearing outstanding leased sockets' close handlers and without waiting for them to drain. Socket close callbacks are delivered after socket disposal in `lib/common/socket.c:521`, `lib/common/socket.c:524`, and `lib/common/socket.c:526`, so a leased socket closed after pool disposal still runs the stale `on_close`.

The reproducer confirms this path is reachable because callers keep leased sockets until explicit return, detach, or close at `lib/common/socketpool.c:584` and `lib/common/socketpool.c:620`, while disposal sites call `h2o_socketpool_dispose` unconditionally, including `lib/handler/proxy.c:130`, `lib/handler/fastcgi.c:827`, and `lib/core/config.c:318`.

## Why This Is A Real Bug
The callback reads freed pool-owned memory on a normal asynchronous close path, not on an impossible or purely theoretical state. The API explicitly allows leased sockets to outlive the pool object until callers return, detach, or close them. Once disposal frees the targets first, any later close callback can corrupt memory or crash the process.

## Fix Requirement
Ensure pool target storage remains valid until all leased sockets that may execute `on_close` have drained, or remove the callback's dependency on `pool->targets.entries` so post-dispose closes cannot dereference freed pool memory.

## Patch Rationale
The patch makes disposal safe against outstanding leased sockets by breaking the use-after-free condition described in the reproducer. The required property is that `on_close` no longer observes freed target storage after `h2o_socketpool_dispose`, either by deferring target reclamation until leased sockets drain or by making the callback self-contained and independent from pool target memory. This directly closes the reproduced crash primitive at `lib/common/socketpool.c:396`.

## Residual Risk
None

## Patch
- `011-dispose-frees-pool-targets-before-async-close-callback-runs.patch` prevents `on_close` from dereferencing freed pool target storage after `h2o_socketpool_dispose`
- The change is scoped to the socket-pool lifecycle path in `lib/common/socketpool.c`
- The patched behavior preserves asynchronous socket close handling while removing the post-dispose use-after-free condition