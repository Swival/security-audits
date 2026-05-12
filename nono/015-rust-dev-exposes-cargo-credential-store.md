# rust-dev exposes Cargo credential store

## Classification

security_control_failure, high severity, confidence certain

## Affected Locations

`crates/nono-cli/data/policy.json:402`

## Summary

The `rust-dev` profile includes the `rust_runtime` group, which granted read access to all of `~/.cargo`. Cargo registry tokens are stored under `~/.cargo/credentials` and `~/.cargo/credentials.toml`, so a sandboxed child process using `rust-dev` could read credentials that the required `deny_credentials` group is intended to block.

## Provenance

Verified by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- The `rust-dev` profile is selected for a sandboxed process.
- The host has Cargo credential files under `~/.cargo`.

## Proof

- `rust-dev` extends `default`, which includes the required `deny_credentials` group.
- `rust-dev` also includes `rust_runtime`.
- Before the patch, `rust_runtime` allowed read access to `~/.cargo`.
- Group resolution converts `allow.read` entries into readable filesystem capabilities.
- Enforcement grants those capabilities on Linux through Landlock `PathBeneath` and on macOS through `file-read*` allow rules.
- Existing deny controls only cover explicit `deny.access` entries, and Cargo credential files were not listed there.
- Therefore, a sandboxed `rust-dev` child process could read `~/.cargo/credentials` or `~/.cargo/credentials.toml`.

## Why This Is A Real Bug

The policy states that `deny_credentials` blocks access to cryptographic keys, tokens, and cloud credentials, and it is required by the base profile. Cargo registry tokens are credentials. Granting blanket read access to `~/.cargo` created a deterministic allow path to those tokens, causing the credential-blocking control to fail open for `rust-dev`.

## Fix Requirement

- Do not grant blanket read access to `~/.cargo`.
- Allow only non-secret Cargo runtime subpaths required for Rust development.
- Explicitly deny Cargo credential files.

## Patch Rationale

The patch narrows `rust_runtime` from `~/.cargo` to non-secret Cargo subpaths:

- `~/.cargo/bin`
- `~/.cargo/registry`
- `~/.cargo/git`

This is the load-bearing fix on Linux, where Landlock cannot express deny-within-allow: shrinking the allow-list is the only way to keep the credential files out of the granted read set.

The patch also adds the credential files to `deny_credentials.deny.access`:

- `~/.cargo/credentials`
- `~/.cargo/credentials.toml`

On macOS, Seatbelt honours these denies through the explicit deny rules layered after the allow rules. On Linux they have no enforcement effect today, but listing them keeps the credential inventory complete and protects against a future regression that re-widens `rust_runtime`.

Together these changes preserve Rust toolchain usability while ensuring Cargo token files remain covered by the required credential deny policy.

## Residual Risk

None

## Patch

```diff
diff --git a/crates/nono-cli/data/policy.json b/crates/nono-cli/data/policy.json
index 1af7e32..4fff7da 100644
--- a/crates/nono-cli/data/policy.json
+++ b/crates/nono-cli/data/policy.json
@@ -26,7 +26,9 @@
           "~/.keys",
           "~/.pki",
           "~/.terraform.d",
-          "~/.config/op"
+          "~/.config/op",
+          "~/.cargo/credentials",
+          "~/.cargo/credentials.toml"
         ]
       }
     },
@@ -399,7 +401,9 @@
       "description": "Rust toolchain paths",
       "allow": {
         "read": [
-          "~/.cargo",
+          "~/.cargo/bin",
+          "~/.cargo/registry",
+          "~/.cargo/git",
           "~/.rustup"
         ]
       }
```