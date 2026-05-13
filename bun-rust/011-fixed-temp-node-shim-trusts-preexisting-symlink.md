# Fixed Temp Node Shim Trusts Preexisting Symlink

## Classification

Privilege escalation, high severity.

Confidence: certain.

## Affected Locations

`src/install/lib.rs:651`

## Summary

`RunCommand::create_fake_temporary_node_executable` used a predictable POSIX temp path, `RunCommand::BUN_NODE_DIR`, for the temporary `node`/`bun` shim directory. If an entry already existed at `/tmp/bun-node[-sha]/node`, the code accepted `EEXIST` without validating ownership, directory permissions, or the symlink target, then added that directory to lifecycle-script `PATH`.

A lower-privileged local attacker sharing `/tmp` could precreate the directory and `node` entry so victim lifecycle scripts resolved `node` to attacker-controlled code.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- POSIX host using a shared sticky temp directory such as `/tmp`.
- Predictable `RunCommand::BUN_NODE_DIR` path is absent, attacker-owned, or otherwise precreatable.
- Victim runs Bun lifecycle scripts on a host where Bun needs to create/use the fake temporary `node` shim.
- Lifecycle script invokes `node` through `PATH`.

## Proof

The vulnerable implementation defines a fixed temp directory such as `/tmp/bun-node` or `/tmp/bun-node-<sha>` and creates `node` and `bun` links inside it.

Before the patch, the POSIX loop did:

```rust
match bun_sys::symlink(argv0_z, dest) {
    Ok(()) => break,
    Err(e) if e.get_errno() == bun_sys::E::EEXIST => break,
    Err(_) if !retried => {
        let _ = bun_sys::mkdir(DIR_Z, 0o755);
        retried = true;
    }
    Err(_) => return Ok(()),
}
```

This means an attacker could precreate `/tmp/bun-node/node` as a symlink or executable pointing to attacker-controlled code. When the victim later ran Bun lifecycle scripts, Bun treated `EEXIST` as success, appended `BUN_NODE_DIR` to the lifecycle `PATH`, and script resolution of `node` executed the attacker-controlled target as the victim.

The reproduced path confirms lifecycle propagation:

- `src/install/PackageManager.rs:1201` calls the helper.
- `src/install/PackageManager.rs:1206` stores the modified `PATH`.
- `src/install/PackageManager/PackageManagerLifecycle.rs:436` clones that environment.
- `src/install/PackageManager/PackageManagerLifecycle.rs:461` carries the modified `PATH` into lifecycle-script `envp`.
- `src/install/lifecycle_script_runner.rs:565` executes lifecycle scripts through a shell using that `envp`.

## Why This Is A Real Bug

The temp directory name is predictable and located in a shared writable location. The old code trusted preexisting filesystem state in that directory. Treating `EEXIST` as success allowed an unprivileged local user to control the `node` executable selected by a later victim’s lifecycle script.

This crosses a privilege boundary whenever the victim user has more privileges than the attacker, because the attacker-controlled binary runs under the victim’s account during lifecycle script execution.

## Fix Requirement

The shim setup must not trust attacker-created entries in a shared temp directory. It must either:

- create and use a private directory with restrictive permissions, or
- validate existing directory ownership and permissions and verify existing links target the intended Bun executable before adding the directory to `PATH`.

## Patch Rationale

The patch hardens the POSIX path by validating the directory before use and validating existing links before accepting them.

It now creates `BUN_NODE_DIR` with mode `0700`. If the directory already exists, it performs `lstat` and refuses to use it unless all are true:

- existing path is a directory,
- owner UID matches the current process UID,
- group/other write bits are not set.

For each `node` and `bun` link, `EEXIST` is no longer accepted blindly. The code calls `readlink` and only accepts the existing entry if it already points to the current Bun executable path. Any mismatch causes the helper to return without appending the unsafe shim path.

This prevents attacker-owned directories and attacker-controlled `node` entries from being trusted.

## Residual Risk

None

## Patch

```diff
diff --git a/src/install/lib.rs b/src/install/lib.rs
index 042aff5496..d9cca735d9 100644
--- a/src/install/lib.rs
+++ b/src/install/lib.rs
@@ -648,15 +648,34 @@ impl RunCommand {
                 ZStr::from_static(B)
             };
 
+            match bun_sys::mkdir(DIR_Z, 0o700) {
+                Ok(()) => {}
+                Err(e) if e.get_errno() == bun_sys::E::EEXIST => {
+                    let stat = match bun_sys::lstat(DIR_Z) {
+                        Ok(stat) => stat,
+                        Err(_) => return Ok(()),
+                    };
+                    if bun_sys::kind_from_mode(stat.st_mode as bun_sys::Mode)
+                        != bun_sys::FileKind::Directory
+                        || stat.st_uid != bun_sys::c::getuid()
+                        || ((stat.st_mode as bun_sys::Mode) & 0o022) != 0
+                    {
+                        return Ok(());
+                    }
+                }
+                Err(_) => return Ok(()),
+            }
+
             for dest in [NODE_LINK, BUN_LINK] {
-                let mut retried = false;
                 loop {
                     match bun_sys::symlink(argv0_z, dest) {
                         Ok(()) => break,
-                        Err(e) if e.get_errno() == bun_sys::E::EEXIST => break,
-                        Err(_) if !retried => {
-                            let _ = bun_sys::mkdir(DIR_Z, 0o755);
-                            retried = true;
+                        Err(e) if e.get_errno() == bun_sys::E::EEXIST => {
+                            let mut existing_target = bun_paths::PathBuffer::uninit();
+                            match bun_sys::readlink(dest, &mut existing_target) {
+                                Ok(len) if &existing_target[..len] == argv0_z.as_bytes() => break,
+                                _ => return Ok(()),
+                            }
                         }
                         Err(_) => return Ok(()),
                     }
```