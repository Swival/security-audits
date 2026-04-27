# Environment Rollback Skipped On Start Failure

## Classification

Data integrity bug, medium severity.

## Affected Locations

`library/std/src/sys/process/uefi.rs:189`

## Summary

`std::process::Command::output` on UEFI temporarily applies command-specific environment changes before starting the child image. If `cmd.start_image()` returns `Err`, the `?` operator returns immediately and skips the rollback block, leaving the parent process / UEFI shell environment modified.

## Provenance

Verified from supplied source, reproduced behavior summary, and patch.

Scanner provenance: https://swival.dev

Confidence: certain.

## Preconditions

- The command has environment changes, such as `.env(...)`, `.env_remove(...)`, or `.env_clear()`.
- `Image::start_image` returns `Err` after the temporary environment changes have been applied.

## Proof

In `output`, `env_changes(&command.env)` computes the old and new environment values. The code then applies each temporary change with `crate::env::set_var` or `crate::env::remove_var`.

Before the patch, execution then reached:

```rust
let stat = cmd.start_image()?;
```

If `cmd.start_image()` returned `Err`, the `?` operator returned from `output` immediately. The rollback block that restores old environment values was located after that fallible call, so it was skipped.

`Image::start_image` can return `Err` before invoking UEFI `StartImage`, including through:

- `self.update_st_crc32()?`
- `boot_services().ok_or_else(...)?`

`update_st_crc32` can propagate `CalculateCrc32` errors as `io::Error`.

The environment mutation is externally meaningful because UEFI environment writes call the shell environment setter in `library/std/src/sys/env/uefi.rs`.

## Why This Is A Real Bug

The temporary environment is intended to be scoped to the command execution. A setup failure in `start_image` violates that scope by leaving the modified environment in place after `Command::output` returns an error.

Later environment reads or later commands can observe values that should have been restored. This can corrupt process state and cause subsequent behavior to depend on a failed command attempt.

The reproduced evidence supports rollback being skipped on `start_image` setup errors. It does not require the child image to run.

## Fix Requirement

Rollback must run on all paths after temporary environment mutation, including when `cmd.start_image()` returns `Err`.

Acceptable approaches include:

- Store the `Result`, perform rollback, then apply `?`.
- Use a guard whose `Drop` restores the environment.
- Match on the result and restore before returning either success or error.

## Patch Rationale

The patch changes:

```rust
let stat = cmd.start_image()?;
```

to:

```rust
let stat = cmd.start_image();
```

This preserves the `Result` instead of returning early. The existing rollback block then always runs after `start_image` completes, regardless of whether it returned `Ok` or `Err`.

After rollback, the patch adds:

```rust
let stat = stat?;
```

This restores the original error propagation behavior after the environment has been restored.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/process/uefi.rs b/library/std/src/sys/process/uefi.rs
index 88dd4c899b3..d9f0f2f3759 100644
--- a/library/std/src/sys/process/uefi.rs
+++ b/library/std/src/sys/process/uefi.rs
@@ -185,7 +185,7 @@ pub fn output(command: &mut Command) -> io::Result<(ExitStatus, Vec<u8>, Vec<u8>
         }
     }
 
-    let stat = cmd.start_image()?;
+    let stat = cmd.start_image();
 
     // Rollback any env changes
     if let Some(e) = env {
@@ -197,6 +197,7 @@ pub fn output(command: &mut Command) -> io::Result<(ExitStatus, Vec<u8>, Vec<u8>
         }
     }
 
+    let stat = stat?;
     let stdout = cmd.stdout()?;
     let stderr = cmd.stderr()?;
```