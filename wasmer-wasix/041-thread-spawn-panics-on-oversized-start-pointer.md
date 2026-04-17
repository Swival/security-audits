# Thread spawn panics on oversized start pointer

## Classification
- Type: error-handling bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/wasix/src/syscalls/wasix/thread_spawn.rs:164`

## Summary
`thread_spawn_v2` accepts a caller-controlled `start_ptr` and propagates its offset into the thread start path. When that offset exceeds `i32::MAX`, the later conversion in the thread entry path uses `unwrap()` on a fallible `try_into()`, causing a panic in the spawned host worker thread instead of returning `Errno::Overflow`.

## Provenance
- Verified from the supplied source-based reproducer and patch requirement
- Scanner: https://swival.dev

## Preconditions
- Attacker controls `start_ptr`
- The `start_ptr` offset exceeds the `i32` range
- Execution reaches the WASIX thread start path, including `wasi_thread_start`

## Proof
The reproduced path is:

```text
thread_spawn_v2
  -> thread_spawn_internal_from_wasi
  -> thread_spawn_internal_using_layout
  -> call_module_internal
```

At the failing conversion, `start_ptr_offset.try_into().map_err(|_| Errno::Overflow).unwrap()` panics when the offset cannot fit in `i32`.

The reproducer confirms this is practically reachable when:
1. The `Memory64` WASIX ABI is used
2. `wasi_thread_start` is exported
3. The `ThreadStart` struct is placed at a valid mapped address above `i32::MAX`
4. `thread_spawn_v2` is invoked

Observed impact:
- The spawned host worker thread panics
- No `catch_unwind` is present on the execution path
- `WasiThreadHandle::drop` marks the thread finished successfully, so failure can be misreported as success

## Why This Is A Real Bug
This is not a theoretical assertion failure. The overflow is attacker-reachable through a caller-supplied pointer in a valid ABI configuration (`Memory64`), and the panic occurs in normal runtime code rather than behind debug-only checks. The resulting behavior is worse than an errno failure: it aborts the worker thread unexpectedly and corrupts thread outcome bookkeeping by recording success on drop.

## Fix Requirement
Replace the fallible conversion `unwrap()` with normal error propagation and reject oversized `start_ptr` offsets before spawning, returning `Errno::Overflow` instead of panicking.

## Patch Rationale
The patch in `041-thread-spawn-panics-on-oversized-start-pointer.patch` removes panic-based handling from the oversized offset path and converts it into an explicit overflow error before thread execution proceeds. This preserves intended syscall error semantics and avoids worker-thread panic and false-success completion state.

## Residual Risk
None

## Patch
- Patch file: `041-thread-spawn-panics-on-oversized-start-pointer.patch`
- Intended effect: replace the panic-triggering conversion with checked error propagation and fail thread spawn with `Errno::Overflow` for oversized `start_ptr` values