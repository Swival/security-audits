# Relative dependency paths bypass caller directory

## Classification
- Type: trust-boundary violation
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/wasix/src/state/linker.rs:1706`

## Summary
`dylink.0` `needed` entries containing a slash were resolved by `locate_module` without using the requesting module's directory. Instead, non-absolute paths flowed into `fs.relative_path_to_absolute(...)`, which anchors resolution to the guest current directory / process filesystem context. A module could therefore request `subdir/libx.so` and have it loaded from `<guest cwd>/subdir/libx.so` rather than from the caller module's parent directory.

## Provenance
- Verified from the reported source location and dependency-loading path in `lib/wasix/src/state/linker.rs`
- Reproduced against the existing code path using the filesystem normalization behavior in `lib/wasix/src/fs/mod.rs`
- Reference: https://swival.dev

## Preconditions
- The needed module name contains a slash
- The path is relative, not absolute
- The guest current directory differs from the requesting module's directory

## Proof
The reproduced flow is:
- `dylink.0` `needed` entries are passed into `LinkerState::load_module_tree`, which calls `locate_module`
- For slash-containing non-absolute paths, `locate_module` previously skipped `$ORIGIN` / caller-directory handling and called filesystem normalization directly
- `relative_path_to_absolute` resolves relative paths against the guest current directory, not the requesting module location, as shown by the filesystem implementation
- The resulting path is opened and the bytes are loaded via `runtime.load_hashed_module_sync`, so the incorrect resolution directly influences which dependency is executed

Observed effect:
- `subdir/libx.so` resolves to `<guest cwd>/subdir/libx.so`
- It does not resolve to `<calling module parent>/subdir/libx.so`

## Why This Is A Real Bug
This is a real dependency-resolution flaw because the loader treats caller-supplied relative dependency paths inconsistently:
- Bare library names use caller-aware search logic such as `$ORIGIN` / RUNPATH
- Slash-containing relative names bypass that caller context entirely
- The chosen module therefore depends on ambient process filesystem state instead of the requesting module's location

That creates a dependency-confusion condition where a module-controlled `needed` entry can escape caller-local resolution and select an unintended library whenever the guest current directory is attacker-influenced or otherwise different from the caller directory.

## Fix Requirement
Resolve slash-containing relative dependency paths against `calling_module_path`'s parent directory before any fallback to process-root or guest-current-directory normalization.

## Patch Rationale
The patch updates `locate_module` so that when a dependency path contains a slash and is not absolute, it first joins that path against the parent directory of `calling_module_path`. This restores expected caller-relative semantics for explicit relative library paths while preserving existing behavior for absolute paths and bare library names.

## Residual Risk
None

## Patch
Patched in `005-relative-library-paths-ignore-calling-module-directory.patch`.