# Predictable /tmp Script File Enables Local Code Injection

## Classification

Low severity code execution (defense in depth).

Confidence: certain.

Note: this code path is gated on `bun_core::Environment::ENABLE_FUZZILLI`, a compile-time constant that is `false` in production builds. It is only enabled in dedicated fuzzing builds (`src/bun_core/lib.rs:600`). The hardening below is still correct, but the practical impact on shipped builds is nil; the affected binary is the special fuzzilli build that runs untrusted JS by design.

## Affected Locations

`src/runtime/cli/fuzzilli_command.rs:64`

## Summary

`FuzzilliCommand::exec` created a fuzzilli REPRL script at the fixed shared pathname `/tmp/bun-fuzzilli-reprl.js` using `O::CREAT | O::WRONLY | O::TRUNC`. Because the open was not exclusive and did not reject symlinks, a lower-privileged local attacker sharing `/tmp` could precreate or replace that pathname before a privileged fuzzilli run. The privileged process would then write to and later execute the predictable path.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- Fuzzilli mode is enabled.
- A privileged fuzzilli run uses shared `/tmp`.
- A lower-privileged local attacker can create or replace `/tmp/bun-fuzzilli-reprl.js` before the privileged run.
- REPRL file descriptor availability checks pass.

## Proof

The vulnerable flow is:

- `src/runtime/cli/fuzzilli_command.rs:64` opens `/tmp/bun-fuzzilli-reprl.js` via `openat`.
- The flags are `O::CREAT | O::WRONLY | O::TRUNC`, without `O::EXCL` or `O::NOFOLLOW`.
- If an attacker precreates the path, the privileged process opens the existing inode and truncates/writes it; the open does not reset ownership or mode.
- `src/runtime/cli/fuzzilli_command.rs:96` then invokes `RunCommand::boot` with the fixed pathname bytes `b"/tmp/bun-fuzzilli-reprl.js"`.
- `src/runtime/cli/run_command.rs:1432` loads the entry point by path.
- `src/bundler/entry_points.rs:327` generates a `bun:main` wrapper importing that path.

A lower-privileged attacker can therefore arrange for attacker-controlled JavaScript at the fixed path to be evaluated by the privileged fuzzilli Bun process.

## Why This Is A Real Bug

The code crosses a privilege boundary through a predictable file in a world-shared directory. The operation is not atomic with respect to file ownership and identity because the file is opened by name without exclusivity. Execution is also path-based, so the process later trusts the same attacker-controllable namespace rather than an already-verified private file descriptor.

This is sufficient for local code injection under the stated fuzzilli preconditions.

## Fix Requirement

The temporary script must be created in a way that prevents attacker precreation or symlink substitution.

At minimum, creation must:

- Use exclusive creation with `O_EXCL`.
- Reject symlink traversal with `O_NOFOLLOW`.
- Use restrictive permissions such as `0600`.

A stronger design would use a private temporary directory or execute from a verified file descriptor instead of a shared fixed path.

## Patch Rationale

The patch changes the file creation flags from:

```rust
O::CREAT | O::WRONLY | O::TRUNC
```

to:

```rust
O::CREAT | O::WRONLY | O::TRUNC | O::EXCL | O::NOFOLLOW
```

and changes the mode from `0o644` to `0o600`.

`O::EXCL` makes the open fail if `/tmp/bun-fuzzilli-reprl.js` already exists, preventing attacker precreation from being reused. `O::NOFOLLOW` prevents the final pathname component from being a symlink. `0o600` avoids making the generated script world-readable or writable through permissive file mode bits.

## Residual Risk

None.

## Patch

```diff
diff --git a/src/runtime/cli/fuzzilli_command.rs b/src/runtime/cli/fuzzilli_command.rs
index 7006a4e49e..47b5f03a05 100644
--- a/src/runtime/cli/fuzzilli_command.rs
+++ b/src/runtime/cli/fuzzilli_command.rs
@@ -65,8 +65,8 @@ impl FuzzilliCommand {
             let temp_file_fd: Fd = match sys::openat(
                 temp_dir_fd,
                 zstr!("bun-fuzzilli-reprl.js"),
-                O::CREAT | O::WRONLY | O::TRUNC,
-                0o644,
+                O::CREAT | O::WRONLY | O::TRUNC | O::EXCL | O::NOFOLLOW,
+                0o600,
             ) {
                 Ok(fd) => fd,
                 Err(_) => {
```