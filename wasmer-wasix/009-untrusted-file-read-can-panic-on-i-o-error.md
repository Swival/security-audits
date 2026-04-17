# Untrusted file read can panic on I/O error

## Classification
- Type: error-handling bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/wasix/src/os/command/builtins/cmd_wasmer.rs:80`

## Summary
`wasmer run <FILE>` reads attacker-controlled filesystem input. After a successful `open()`, the code calls `file.read_to_end(&mut data).await.unwrap()`. If the read fails, the process panics instead of returning `SpawnError`. A directory path on Unix is a valid trigger because open-for-read succeeds but the subsequent read returns `EISDIR`.

## Provenance
- Verified finding reproduced from source and runtime behavior
- Scanner provenance: https://swival.dev

## Preconditions
- Attacker controls the `wasmer run` file path
- The chosen path opens successfully for read
- The subsequent `read_to_end()` returns an I/O error

## Proof
The reachable path is:
1. `what` is attacker-controlled via `exec()`
2. `run()` resolves it to `file_path`
3. `fs.new_open_options().read(true).open(&file_path)` succeeds
4. `file.read_to_end(&mut data).await.unwrap()` executes
5. Any read error triggers panic

Reproduction evidence:
- The opened object is backed by host FS file handling in `lib/virtual-fs/src/host_fs.rs:297`, `lib/virtual-fs/src/host_fs.rs:322`, and reads via `tokio::fs::File` in `lib/virtual-fs/src/host_fs.rs:563`
- On Unix, opening a directory read-only succeeds, but reading from it fails with `EISDIR` / `Is a directory`
- This exactly matches the failing operation sequence in the vulnerable code path

## Why This Is A Real Bug
This is externally reachable through normal CLI input: `wasmer run <FILE>`. The failure occurs after successful validation and open, so it is not blocked earlier. `unwrap()` converts a recoverable I/O failure into a process panic, causing denial of service in the command handler rather than a structured `SpawnError`.

## Fix Requirement
Replace the `unwrap()` on `read_to_end()` with proper error propagation that returns `SpawnError` on read failure.

## Patch Rationale
The patch changes the read path in `lib/wasix/src/os/command/builtins/cmd_wasmer.rs` to handle `read_to_end()` failure explicitly and propagate it as `SpawnError`. This preserves existing control flow, prevents panic on malformed or hostile filesystem input, and aligns read-error handling with the surrounding fallible operations.

## Residual Risk
None

## Patch
- Patch file: `009-untrusted-file-read-can-panic-on-i-o-error.patch`