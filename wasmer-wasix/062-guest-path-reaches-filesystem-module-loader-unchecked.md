# Guest `dlopen` path bypasses guest file-access checks

## Classification
- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/wasix/src/syscalls/wasix/dlopen.rs:40`

## Summary
`dlopen` accepted an arbitrary guest-provided path string and forwarded it directly into the filesystem-backed module loader via `DlModuleSpec::FileSystem`, without enforcing the guest-visible filesystem sandbox. This allowed a guest to load a side module from any path reachable under the runtime root filesystem, even when equivalent guest file syscalls would deny access because the path was outside configured preopens.

## Provenance
- Verified from the provided finding and reproducer details
- Reproduced against the described code path in `lib/wasix/src/syscalls/wasix/dlopen.rs:40`
- Scanner source: https://swival.dev

## Preconditions
- Dynamic linking is enabled
- The guest can invoke `dlopen` with an arbitrary path string
- The runtime root filesystem exposes content beyond the guest's preopened subset
- A valid dylink-enabled wasm side module exists at a path reachable from the root filesystem but outside guest-authorized file access

## Proof
`dlopen` read the guest pointer into `path`, converted it with `Path::new(&path)`, and built `DlModuleSpec::FileSystem { module_spec, ld_library_path }` directly. No path authorization, confinement, or guest-access validation occurred before `linker.load_module(location, &mut ctx)`.

This was practically triggerable when the runtime mounted a broader root filesystem than the guest preopens. In that configuration:
- normal guest file syscalls remained confined by preopen and path-rights checks
- `dlopen` instead resolved through `root_fs`
- a guest could therefore request a module path outside its visible sandbox and still have the loader open it

Reproduction confirmed that host-backed filesystems still confine traversal to their configured root in `lib/virtual-fs/src/host_fs.rs:79`, so this is not host-root escape. The bug is the missing guest-to-loader authorization check that bypasses the intended guest-visible file access policy.

## Why This Is A Real Bug
The vulnerable behavior crosses a trust boundary: untrusted guest input selects a filesystem-backed module load target, but the loader path was not subjected to the same authorization model as normal guest filesystem access. As a result, `dlopen` could access and execute wasm modules intentionally hidden from the guest. That is a real privilege expansion within the runtime's mounted filesystem, even though host filesystem traversal remains bounded by the configured root.

## Fix Requirement
Before invoking filesystem-backed module loading, `dlopen` must validate and confine the requested module path and library search paths against the guest-visible filesystem policy. At minimum, it must reject absolute paths and path traversal that escapes authorized locations, and it must ensure module resolution is only permitted through paths the guest could legitimately open.

## Patch Rationale
The patch in `062-guest-path-reaches-filesystem-module-loader-unchecked.patch` adds validation at the `dlopen` entry point so guest-supplied module paths are checked against the guest's accessible filesystem view before constructing `DlModuleSpec::FileSystem`. This closes the authorization gap at the boundary where guest-controlled strings become loader filesystem inputs, while preserving valid dynamic loading from allowed locations.

## Residual Risk
None

## Patch
- Added guest-path validation in `lib/wasix/src/syscalls/wasix/dlopen.rs`
- Rejected unauthorized filesystem module paths before `DlModuleSpec::FileSystem` reaches `linker.load_module(...)`
- Constrained loading behavior to paths consistent with guest-visible filesystem access rules
- Captured in `062-guest-path-reaches-filesystem-module-loader-unchecked.patch`