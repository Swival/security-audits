# stderr uses stdout configuration

## Classification

Logic error, high severity, confirmed.

## Affected Locations

`library/std/src/sys/process/motor.rs:115`

## Summary

Motor OS process spawning ignores the caller-configured `stderr` field. In `Command::spawn`, the `stderr` runtime descriptor is built from `self.stdout.as_ref()` instead of `self.stderr.as_ref()`, causing child stderr to follow stdout configuration or the default rather than the explicit stderr setting.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

Caller configures `Command` stderr differently from stdout.

The bug also triggers when only stderr is configured and stdout is left unset, because `self.stderr` is never read.

## Proof

`Command::stdout` and `Command::stderr` store separate fields:

```rust
pub fn stdout(&mut self, stdout: Stdio) {
    self.stdout = Some(stdout);
}

pub fn stderr(&mut self, stderr: Stdio) {
    self.stderr = Some(stderr);
}
```

During spawn, stdout is computed from `self.stdout`:

```rust
let stdout = if let Some(stdout) = self.stdout.as_ref() {
    stdout.try_clone()?.into_rt()
} else {
    default.try_clone()?.into_rt()
};
```

But stderr is also computed from `self.stdout`:

```rust
let stderr = if let Some(stderr) = self.stdout.as_ref() {
    stderr.try_clone()?.into_rt()
} else {
    default.try_clone()?.into_rt()
};
```

The computed `stderr` value is then passed directly into `moto_rt::process::SpawnArgs`:

```rust
let args = moto_rt::process::SpawnArgs {
    program: self.program.clone(),
    args: self.args.clone(),
    env,
    cwd: self.cwd.clone(),
    stdin,
    stdout,
    stderr,
};
```

Practical trigger on Motor OS:

```rust
Command::new("x")
    .stdout(Stdio::null())
    .stderr(Stdio::piped())
    .spawn()
```

Expected behavior: child stderr is piped.

Actual behavior: child stderr is configured as null because stderr clones stdout’s `Null` configuration.

## Why This Is A Real Bug

The `Command` struct contains distinct `stdout` and `stderr` fields, and public setters write to those distinct fields. `Command::spawn` is expected to honor both independently.

Because `spawn` never reads `self.stderr`, every explicit stderr configuration on Motor OS is ignored. This can discard diagnostics, inherit or null stderr unexpectedly, or fail to create the requested stderr pipe.

The result is observable through returned `StdioPipes`: when stderr is configured as a pipe but stdout is null or defaulted, the caller does not receive the expected stderr pipe.

## Fix Requirement

When constructing the `stderr` runtime descriptor in `Command::spawn`, read `self.stderr.as_ref()` rather than `self.stdout.as_ref()`.

## Patch Rationale

The patch changes only the source field used for stderr construction:

```diff
-        let stderr = if let Some(stderr) = self.stdout.as_ref() {
+        let stderr = if let Some(stderr) = self.stderr.as_ref() {
```

This preserves existing cloning, conversion, default fallback, and `SpawnArgs` propagation behavior while making stderr honor the configuration supplied through `Command::stderr`.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/process/motor.rs b/library/std/src/sys/process/motor.rs
index 133633f7bc6..1381e196768 100644
--- a/library/std/src/sys/process/motor.rs
+++ b/library/std/src/sys/process/motor.rs
@@ -121,7 +121,7 @@ pub fn spawn(
         } else {
             default.try_clone()?.into_rt()
         };
-        let stderr = if let Some(stderr) = self.stdout.as_ref() {
+        let stderr = if let Some(stderr) = self.stderr.as_ref() {
             stderr.try_clone()?.into_rt()
         } else {
             default.try_clone()?.into_rt()
```