# Uninitialized datagram flow ID on ordinary HTTP/3 streams

## Classification
- Type: invariant violation
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/http3/server.c:853`

## Summary
`stream_open_cb` allocates and initializes `st_h2o_http3_server_stream_t` for every bidirectional request stream, but leaves `stream->datagram_flow_id` uninitialized. Non-CONNECT requests never assign that field later, yet cleanup code treats `UINT64_MAX` as the required "no datagram flow" sentinel. As a result, ordinary request teardown can read indeterminate storage and use it as a datagram flow key.

## Provenance
- Reproduced from the verified finding and confirmed against source control state in this workspace
- Scanner reference: https://swival.dev

## Preconditions
- A client opens a non-CONNECT bidirectional request stream

## Proof
`stream_open_cb` in `lib/http3/server.c:853` creates the per-stream object and initializes several members, but does not write `stream->datagram_flow_id`.

For ordinary requests, the header-processing path does not assign a datagram flow ID; only CONNECT/UDP tunnel handling does. The stream therefore retains indeterminate bits in `datagram_flow_id`.

During normal teardown, `pre_dispose_request` checks whether `stream->datagram_flow_id != UINT64_MAX` and, if so, performs `kh_get` / `kh_del` against `conn->datagram_flows` using that value (`lib/http3/server.c:467`). That path is reachable for normal request cleanup when the stream enters `CLOSE_WAIT` or is destroyed.

The initially reported alternate path through `finalize_do_send_setup_udp_tunnel` is not a practical non-CONNECT trigger because normal request initialization leaves `req.forward_datagram.write_` unset, causing the early guard in `lib/http3/server.c:1571` to return before the later `datagram_flow_id` check. The bug remains real because the cleanup path alone performs the uninitialized read.

## Why This Is A Real Bug
This is source-grounded undefined behavior: the program reads an uninitialized scalar from heap storage and branches on it. The resulting garbage value is then used as a hash-table lookup key and potentially as a deletion key for `conn->datagram_flows`. Even when this only causes a bogus lookup, it violates the stream-state invariant that non-tunnel streams must carry the sentinel `UINT64_MAX`; if stale bits collide with a live flow ID, cleanup can target the wrong datagram flow entry.

## Fix Requirement
Initialize `stream->datagram_flow_id` to the non-tunnel sentinel `UINT64_MAX` when the stream object is created in `stream_open_cb`.

## Patch Rationale
Setting the field at allocation time restores the intended invariant for all non-CONNECT streams and ensures every later test against `UINT64_MAX` is well-defined. This is the narrowest correct fix because tunnel-specific paths already overwrite the field when a real datagram flow is established.

## Residual Risk
None

## Patch
Patched by initializing the stream sentinel in `004-uninitialized-datagram-flow-id-used-for-non-tunnel-streams.patch`, adding:
- `stream->datagram_flow_id = UINT64_MAX;`

at stream creation in `lib/http3/server.c:853`.