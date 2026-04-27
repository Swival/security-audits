// Bug: Motor OS Command::spawn builds the stderr runtime descriptor from
//      self.stdout.as_ref() instead of self.stderr.as_ref().
// Target: x86_64-unknown-moturus (target_os = "motor"). Toolchain unavailable
//         on host; this PoC mirrors the buggy field selection.
// Expected: stderr derived from self.stderr; piped stderr returned to caller.
// Observed: stderr inherits stdout setting; explicit stderr config ignored.
// Build/run: rustc 108-stderr-uses-stdout-configuration.rs -o /tmp/poc108 \
//            && /tmp/poc108

#[derive(Debug, Clone, PartialEq)]
enum Stdio { Null, Piped, Inherit }

struct Command {
    stdout: Option<Stdio>,
    stderr: Option<Stdio>,
}

fn spawn_buggy(c: &Command) -> (Stdio, Stdio) {
    let default = Stdio::Inherit;
    let stdout = c.stdout.as_ref().cloned().unwrap_or(default.clone());
    // BUG: reads c.stdout for stderr.
    let stderr = c.stdout.as_ref().cloned().unwrap_or(default);
    (stdout, stderr)
}

fn main() {
    let c = Command { stdout: Some(Stdio::Null), stderr: Some(Stdio::Piped) };
    let (out, err) = spawn_buggy(&c);
    println!("requested stderr=Piped; observed stderr={err:?}, stdout={out:?}");
    assert_eq!(out, Stdio::Null);
    assert_eq!(err, Stdio::Null, "BUG REPRODUCED: stderr cloned stdout config");
    println!("BUG REPRODUCED");
}
