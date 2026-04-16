# Imported socket import failure leaks ownership and crashes caller

## Classification
- Type: resource lifecycle bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/common/socket/uv-binding.c.h:263`
- `lib/common/socket/uv-binding.c.h:352`
- `lib/common/socket.c:615`
- `lib/common/socket.c:617`
- `include/h2o/socket.h:295`

## Summary
`h2o_socket_import` accepts caller-populated `h2o_socket_export_t`. When `do_import` reaches `uv_tcp_open` with a supplied fd that libuv rejects, it returns `NULL` after tearing down only the newly allocated wrapper. The original fd is not closed on that path in `do_import`, and `h2o_socket_import` then unconditionally sets `info->fd = -1` and dereferences the returned socket pointer, causing a crash and making the supplied descriptor unrecoverable to the caller.

## Provenance
- Verified from source and reproduced against the public import API surface
- Scanner source: https://swival.dev

## Preconditions
- `h2o_socket_import` is called with caller-controlled `h2o_socket_export_t`
- `info->fd` is a valid TCP fd for which `uv_tcp_open` returns failure

## Proof
- `h2o_socket_import` is publicly exposed via `include/h2o/socket.h:295`, so import data is not restricted to the internal export path.
- In `do_import`, `info->fd` is passed into `uv_tcp_open((uv_tcp_t *)sock->handle, info->fd)`.
- On nonzero return, `do_import` calls `h2o_socket_close(&sock->super)` and returns `NULL` at `lib/common/socket/uv-binding.c.h:352`.
- No `close(info->fd)` occurs on that failure path, so ownership of the caller-supplied fd is not resolved there.
- `h2o_socket_import` then executes `info->fd = -1` at `lib/common/socket.c:615` and dereferences `sock` at `lib/common/socket.c:617` without checking for `NULL`, producing a reproducible null dereference and losing any handle by which the caller could recover the fd.

## Why This Is A Real Bug
The issue is reachable through the committed public API even if the internal export/import happy path does not trigger it. The contract surface permits callers to provide import data directly. Under that supported entrypoint, a `uv_tcp_open` rejection leaves import in an inconsistent ownership state and immediately crashes the process by dereferencing `NULL`. This is not speculative: the failure branch exists in source, is reachable with malformed/manual import data, and has concrete safety impact.

## Fix Requirement
On `uv_tcp_open` failure, the implementation must resolve ownership before returning and the public import wrapper must not invalidate caller state or dereference a null socket. The supplied fd must either be closed on failed adoption or left recoverable to the caller, and `h2o_socket_import` must check the `do_import` result before mutating `info` or using `sock`.

## Patch Rationale
The patch closes `info->fd` in the `uv_tcp_open` failure path so failed adoption does not strand the descriptor. It also ensures the import wrapper handles `NULL` safely before clearing `info->fd` or touching socket fields, preserving correct ownership semantics and removing the null dereference.

## Residual Risk
None

## Patch
- Patch file: `020-imported-socket-leaks-fd-on-uv-tcp-open-failure.patch`
- The patch adds explicit fd cleanup on `uv_tcp_open` failure in `lib/common/socket/uv-binding.c.h`
- The patch guards the `h2o_socket_import` failure path in `lib/common/socket.c` so `info` is not invalidated and `sock` is not dereferenced when import fails