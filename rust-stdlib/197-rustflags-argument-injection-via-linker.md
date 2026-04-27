# rustflags argument injection via linker

## Classification

Vulnerability, medium severity.

## Affected Locations

- `library/stdarch/crates/intrinsic-test/src/common/gen_rust.rs:173`

## Summary

`compile_rust_programs` accepted a caller-controlled `linker` string and appended it verbatim into `RUSTFLAGS` after `-C linker=`. Because Cargo/rustc parse `RUSTFLAGS` as whitespace-separated arguments, a linker value containing spaces could inject additional rustc flags.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Caller supplies `linker` containing whitespace.
- The whitespace-delimited suffix contains valid rustc flag syntax.
- `toolchain` is present, so `compile_rust_programs` proceeds to invoke Cargo.

## Proof

The vulnerable flow is direct:

- `linker` enters `compile_rust_programs` as `Option<&str>`.
- `library/stdarch/crates/intrinsic-test/src/common/gen_rust.rs:173` appends it verbatim after ` -C linker=`.
- `library/stdarch/crates/intrinsic-test/src/common/gen_rust.rs:178` exports the concatenated string as `RUSTFLAGS`.
- Cargo/rustc split `RUSTFLAGS` on whitespace, so spaces in `linker` create additional rustc arguments.

Runtime confirmation reproduced practical injection:

```text
RUSTFLAGS='-Cdebuginfo=0 -C linker=cc --cfg injected -C link-args=-static'
```

A test crate containing:

```rust
#[cfg(injected)]
compile_error!("injected cfg reached");
```

failed with:

```text
error: injected cfg reached
```

The same crate with only `-C linker=cc` succeeded.

## Why This Is A Real Bug

`linker` is intended to populate one rustc option value, `-C linker=<path>`. Instead, whitespace causes the value to escape that option boundary. Subsequent tokens become independent rustc arguments, allowing attacker-chosen build configuration such as `--cfg injected` or other accepted compiler flags.

## Fix Requirement

Prevent `linker` from containing whitespace before interpolating it into `RUSTFLAGS`, or pass rustc arguments through an encoding-preserving mechanism such as `CARGO_ENCODED_RUSTFLAGS`.

## Patch Rationale

The patch rejects any linker string containing whitespace:

```diff
+        if linker.chars().any(char::is_whitespace) {
+            error!("linker must not contain whitespace");
+            return false;
+        }
+
```

This preserves the existing `RUSTFLAGS` construction while enforcing the invariant that the `linker` value remains a single whitespace-delimited rustc argument.

## Residual Risk

None

## Patch

```diff
diff --git a/library/stdarch/crates/intrinsic-test/src/common/gen_rust.rs b/library/stdarch/crates/intrinsic-test/src/common/gen_rust.rs
index 82b97701bb1..41ba8f2d840 100644
--- a/library/stdarch/crates/intrinsic-test/src/common/gen_rust.rs
+++ b/library/stdarch/crates/intrinsic-test/src/common/gen_rust.rs
@@ -170,6 +170,11 @@ pub fn compile_rust_programs(
 
     let mut rust_flags = "-Cdebuginfo=0".to_string();
     if let Some(linker) = linker {
+        if linker.chars().any(char::is_whitespace) {
+            error!("linker must not contain whitespace");
+            return false;
+        }
+
         rust_flags.push_str(" -C linker=");
         rust_flags.push_str(linker);
         rust_flags.push_str(" -C link-args=-static");
```