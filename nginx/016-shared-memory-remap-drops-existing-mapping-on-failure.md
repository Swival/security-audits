# Shared memory remap drops existing mapping on failure

## Classification
- Type: resource lifecycle bug
- Severity: high
- Confidence: certain

## Affected Locations
- `src/os/win32/ngx_shmem.c:108`
- `src/core/ngx_cycle.c:474`
- `src/core/ngx_cycle.c:476`
- `src/core/ngx_cycle.c:495`
- `src/core/ngx_cycle.c:831`
- `src/core/ngx_cycle.c:981`
- `src/os/win32/ngx_process_cycle.c:203`
- `src/event/ngx_event_openssl.c:4318`
- `src/event/ngx_event_openssl_stapling.c:2491`

## Summary
`ngx_shm_remap()` unmaps the current shared-memory view before attempting `MapViewOfFileEx(..., addr)`. If the new mapping fails, the function returns `NGX_ERROR` with the original view already gone, while `shm->handle` remains open and `shm->addr` still refers to the now-unmapped region. During reload failure handling on Windows, nginx can fall back to the old cycle even though that cycle's shared-memory view was just destroyed, leaving shared-memory-backed state inaccessible and potentially causing later invalid memory access.

## Provenance
- Verified from repository source and reproducer-provided control flow
- Reproduced in the reported Windows reload/remap path
- Scanner reference: [Swival Security Scanner](https://swival.dev)

## Preconditions
- `ngx_shm_remap()` is called on an already mapped shared-memory view
- `MapViewOfFileEx(..., addr)` fails for the requested target address
- Reload or another caller continues using cycle state that still references the old shared-memory objects

## Proof
At `src/os/win32/ngx_shmem.c:108`, `ngx_shm_remap()` receives the requested `addr`, calls `UnmapViewOfFile(shm->addr)`, and only then attempts `MapViewOfFileEx(shm->handle, FILE_MAP_WRITE, 0, 0, shm->size.QuadPart, addr)`. On failure, it logs and returns `NGX_ERROR` without restoring the prior mapping.

The reproduced reload path shows this is not a harmless transient failure:
- cycle creation/remap can fail through `src/core/ngx_cycle.c:981`, `src/core/ngx_cycle.c:495`, and `src/core/ngx_cycle.c:831`
- the master then falls back to the old cycle at `src/os/win32/ngx_process_cycle.c:203`
- the new cycle had only copied the same process-local shared-memory pointer and handle values from the old cycle at `src/core/ngx_cycle.c:474` and `src/core/ngx_cycle.c:476`

Therefore, after remap failure, fallback preserves references to a view that has already been unmapped. Subsequent use of shared-memory-derived data, including module state initialized from `shm.addr` at `src/event/ngx_event_openssl.c:4318` and `src/event/ngx_event_openssl_stapling.c:2491`, can dereference unmapped memory.

## Why This Is A Real Bug
This is a concrete lifetime violation, not a theoretical cleanup issue. The function destroys a valid live mapping before proving replacement success. The handle stays open, so object ownership appears intact, but the process mapping is gone. The reproduced control flow shows nginx can keep operating with the old cycle after this failure, making the stale `shm->addr` reachable. That creates at minimum reload-time denial of service and can escalate to invalid memory access in shared-memory-backed features.

## Fix Requirement
The remap path must preserve the existing valid mapping unless and until a replacement mapping is known to exist. Acceptable fixes are:
- map the new view before unmapping the old one, if the platform semantics allow it, or
- if replacement-at-address fails after unmapping, immediately restore a valid mapping and only then return failure

## Patch Rationale
The patch in `016-shared-memory-remap-drops-existing-mapping-on-failure.patch` ensures `ngx_shm_remap()` does not leave the process with no valid shared-memory view on remap failure. It restores or preserves a valid mapping before returning error, so reload fallback cannot retain cycle state that points at an already unmapped region. This directly closes the proven state-loss condition while preserving existing error handling behavior.

## Residual Risk
None

## Patch
- Patch file: `016-shared-memory-remap-drops-existing-mapping-on-failure.patch`
- Required behavior: `src/os/win32/ngx_shmem.c:108` must no longer return failure after dropping the only valid view for `shm->handle`
- Security effect: failed remap no longer destroys the caller's existing shared-memory mapping, preventing stale unmapped `shm->addr` from surviving into reload fallback paths