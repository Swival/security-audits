# Racy lazy initialization of DLL globals

## Classification
- Type: race condition
- Severity: high
- Confidence: certain

## Affected Locations
- `std/internal/windows/advapi32.d:39`
- `std/windows/registry.d:255`
- `std/windows/registry.d:349`
- `std/windows/registry.d:969`

## Summary
`std/internal/windows/advapi32.d` lazily initializes `advapi32.dll` state through mutable module globals without synchronization. `loadAdvapi32()` publishes `hAdvapi32` before `pRegDeleteKeyExW`, so a concurrent caller can observe a non-null DLL handle with a still-null function pointer and then call through that pointer from the registry deletion path.

## Provenance
- Verified from the provided reproducer and patch target in local source context
- Scanner source: [Swival Security Scanner](https://swival.dev)

## Preconditions
- Two threads call into the WOW64-aware registry deletion path on Windows.
- The caller reaches `Key.deleteKey` with `KEY_WOW64_*` flags, causing the `RegDeleteKeyExW` lazy-load path to execute.

## Proof
- `std/internal/windows/advapi32.d:39` defines mutable globals `hAdvapi32` and `pRegDeleteKeyExW`.
- `loadAdvapi32()` checks `!hAdvapi32`, then stores `hAdvapi32 = LoadLibraryA(...)` and only afterward resolves `pRegDeleteKeyExW = GetProcAddress(...)`, with no lock, atomic publication, or one-time init primitive.
- A concrete interleaving is sufficient:
  - Thread A enters `loadAdvapi32()`, successfully stores non-null `hAdvapi32`, then is preempted.
  - Thread B enters `loadAdvapi32()`, observes non-null `hAdvapi32`, skips initialization, returns, and proceeds.
  - Thread B reaches the call site in `std/windows/registry.d:349` and dereferences `pRegDeleteKeyExW` while it is still null.
- This path is reachable from public API `Key.deleteKey` in `std/windows/registry.d:969`, gated by the WOW64 flag handling checked in `std/windows/registry.d:255`.

## Why This Is A Real Bug
The observed state is not merely inconsistent bookkeeping; it creates a direct null function-pointer call on a public multithreaded path. That is an immediate crash and memory-safety failure. The race is reachable in committed code because no synchronization primitive prevents another thread from seeing the partially initialized globals.

## Fix Requirement
Guard initialization and teardown with process-wide synchronization or a Windows one-time initialization primitive, and only publish fully initialized DLL state together so callers cannot observe `hAdvapi32` without a valid `pRegDeleteKeyExW`.

## Patch Rationale
The patch in `083-racy-lazy-initialization-of-dll-globals.patch` should serialize `advapi32` load/free and ensure the function pointer is resolved before the initialized state becomes visible to other threads. That removes the partial-publication window that enables the null call.

## Residual Risk
None

## Patch
- `083-racy-lazy-initialization-of-dll-globals.patch`