# Renumbering leaks replaced descriptor resource

## Classification
- Type: resource lifecycle bug
- Severity: high
- Confidence: certain

## Affected Locations
- `crates/wasi/src/p1.rs:1206`

## Summary
`fd_renumber(from, to)` overwrote an existing descriptor at `to` without running the explicit host-resource destruction path used by `fd_close`. When `to` already referenced a host file, directory, or stream, the displaced resource became unreachable from the WASI preview1 descriptor table but remained live in the underlying host table, causing a persistent resource leak on each successful renumber.

## Provenance
- Verified from the supplied finding and reproducer against the codebase
- Scanner source: https://swival.dev

## Preconditions
- Two valid WASI descriptors exist
- `from != to`
- `to` already references a host-backed resource

## Proof
- `fd_renumber` in `crates/wasi/src/p1.rs:1206` removes `from`, frees that slot, removes `to` from `free`, and inserts the moved descriptor into `used` at `to`.
- `BTreeMap::insert` only returns the displaced `Descriptor` wrapper; it does not invoke the explicit host cleanup required to release the underlying resource.
- The intended destruction path is visible in `fd_close` at `crates/wasi/src/p1.rs:1363`, which removes the descriptor and then explicitly calls the relevant host drop hook.
- Those hooks perform the actual release: `filesystem::HostDescriptor::drop` deletes the table entry in `crates/wasi/src/p2/host/filesystem.rs:306`, and stream drops release table-backed stream resources in `crates/wasi-io/src/impls.rs:121` and `crates/wasi-io/src/impls.rs:250`.
- Because `fd_renumber` skipped those calls for the displaced `to` entry, repeated guest-controlled `open -> open -> renumber` sequences leaked host resources and backing table slots.

## Why This Is A Real Bug
The bug is reachable through a standard guest API and does not depend on undefined behavior or unusual timing. The codebase already establishes that wrapper destruction is insufficient and that explicit host drop hooks are required to release underlying resources. `fd_renumber` violated that invariant for overwritten descriptors, so successful renumbering could indefinitely accumulate live but unreachable host objects until process teardown or resource exhaustion.

## Fix Requirement
Before inserting the moved descriptor at `to`, extract any existing descriptor currently bound to `to` and run the same explicit host-resource drop path used by `fd_close` so the displaced file, directory, or stream is actually released.

## Patch Rationale
The patch updates `fd_renumber` to close any replaced descriptor before overwriting `to`, reusing the established explicit-drop behavior rather than relying on wrapper destruction. This preserves existing renumber semantics while aligning replacement handling with the codebase's only proven resource-release path.

## Residual Risk
None

## Patch
- Applied in `001-renumbering-leaks-replaced-descriptor-resource.patch`
- The patch ensures `fd_renumber` explicitly drops any host-backed descriptor previously stored at `to` before inserting the moved descriptor, preventing unreachable live resources from accumulating.