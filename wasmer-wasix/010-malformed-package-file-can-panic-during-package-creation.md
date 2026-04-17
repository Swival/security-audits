# Malformed package file panic on package creation

## Classification
- Type: error-handling bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/wasix/src/os/command/builtins/cmd_wasmer.rs:86`

## Summary
- `wasmer run <FILE>` can panic when a readable local WEBC passes container parsing but fails semantic package construction.
- The panic is caused by `BinaryPackage::from_webc(&container, &*self.runtime).await.unwrap()`, which aborts command execution instead of returning a `SpawnError`.

## Provenance
- Verified from the provided finding and reproducer against the committed codebase.
- Scanner reference: https://swival.dev

## Preconditions
- User runs `wasmer` on a readable malformed package file.
- The file is accepted as a WEBC container by `from_bytes(...)`.
- Semantic package construction fails inside `BinaryPackage::from_webc(...)`.

## Proof
- In `run()`, input from `what` is resolved to `file_path`, read from disk, and parsed as a container.
- When parsing succeeds, `lib/wasix/src/os/command/builtins/cmd_wasmer.rs:86` calls `BinaryPackage::from_webc(&container, &*self.runtime).await.unwrap()`.
- `BinaryPackage::from_webc(...)` can return `Err` for malformed package semantics because it propagates failures from package resolution and tree loading in `lib/wasix/src/bin_factory/binary_package.rs:230`.
- A concrete reachable case exists when the WEBC manifest references a missing atom; `load_package_tree()` checks `webc.get_atom(&atom_name)` and returns an error if absent in `lib/wasix/src/runtime/package_loader/load_package_tree.rs:181` and `lib/wasix/src/runtime/package_loader/load_package_tree.rs:190`.
- That `Err` reaches the `unwrap()`, causing a panic during `wasmer run <FILE>` instead of a handled `SpawnError`.

## Why This Is A Real Bug
- The input path is user-reachable through normal CLI usage on a local file.
- The failure mode is not limited to unreadable or unparsable files; a syntactically valid WEBC with inconsistent metadata is sufficient.
- Panicking on malformed package content is a denial-of-service against the command path and violates expected CLI error handling.

## Fix Requirement
- Remove the `unwrap()` on `BinaryPackage::from_webc(...)`.
- Convert package-construction failures into a normal error return path, yielding `SpawnError` rather than panicking.

## Patch Rationale
- The patch replaces the unchecked unwrap with explicit error propagation from package creation.
- This preserves existing behavior for valid packages while making malformed package semantics return a handled command error.

## Residual Risk
- None

## Patch
- Patch file: `010-malformed-package-file-can-panic-during-package-creation.patch`