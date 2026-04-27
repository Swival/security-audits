# Generated Rust Injection Via Intrinsic Name

## Classification

Vulnerability, medium severity.

## Affected Locations

`library/stdarch/crates/intrinsic-test/src/common/gen_rust.rs:91`

## Summary

`write_main_rs` generated Rust source using intrinsic names directly in both string-literal and identifier contexts. A crafted intrinsic name containing Rust syntax metacharacters could break out of the generated `println!` string literal and inject Rust statements into `rust_programs/src/main.rs`, causing generated source corruption and build-breaking code injection.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

An intrinsic name contains Rust syntax metacharacters and reaches `write_main_rs`.

## Proof

`binary` comes from the `intrinsics` iterator passed to `write_main_rs`. Before the patch, it was emitted raw into generated Rust:

```rust
println!("{binary}");
run_{binary}();
```

A reproduced payload used as an intrinsic name was:

```text
safe_name"); ::std::fs::write("/tmp/stdarch_intrinsic_name_poc", "owned").unwrap(); println!("after
```

Running the generator with `--generate-only` produced injected generated Rust:

```rust
println!("safe_name"); ::std::fs::write("/tmp/stdarch_intrinsic_name_poc", "owned").unwrap(); println!("after");
run_safe_name"); ::std::fs::write("/tmp/stdarch_intrinsic_name_poc", "owned").unwrap(); println!("after();
```

This proves the raw intrinsic name escapes the generated string literal and injects Rust statements. The same raw value also corrupts identifier/expression contexts such as `run_{binary}()`.

## Why This Is A Real Bug

The vulnerable code path is reached for every intrinsic emitted by `write_main_rs`. There was no escaping before string-literal formatting and no validation before identifier formatting. Therefore, an intrinsic name with quotes or statement syntax changes the generated Rust program rather than being treated as data.

The reproduced output demonstrates source-level injection and denial of service through build corruption.

## Fix Requirement

Validate intrinsic names before using them as Rust identifiers, and escape intrinsic-name output when emitting it as a string literal.

## Patch Rationale

The patch adds `is_rust_identifier`, which permits only ASCII Rust identifier characters with a valid first character:

```rust
fn is_rust_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some('_' | 'a'..='z' | 'A'..='Z'))
        && chars.all(|c| matches!(c, '_' | 'a'..='z' | 'A'..='Z' | '0'..='9'))
}
```

`write_main_rs` now rejects invalid intrinsic names with `InvalidInput` before emitting them into generated Rust:

```rust
if !is_rust_identifier(binary) {
    return Err(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!("invalid Rust identifier: {binary:?}"),
    ));
}
```

The generated display line now uses debug formatting:

```rust
writeln!(w, "    println!({binary:?});")?;
```

This serializes the intrinsic name as a valid Rust string literal and prevents string-literal breakout.

## Residual Risk

None

## Patch

```diff
diff --git a/library/stdarch/crates/intrinsic-test/src/common/gen_rust.rs b/library/stdarch/crates/intrinsic-test/src/common/gen_rust.rs
index 82b97701bb1..3f39061c52f 100644
--- a/library/stdarch/crates/intrinsic-test/src/common/gen_rust.rs
+++ b/library/stdarch/crates/intrinsic-test/src/common/gen_rust.rs
@@ -16,6 +16,12 @@ macro_rules! concatln {
     };
 }
 
+fn is_rust_identifier(name: &str) -> bool {
+    let mut chars = name.chars();
+    matches!(chars.next(), Some('_' | 'a'..='z' | 'A'..='Z'))
+        && chars.all(|c| matches!(c, '_' | 'a'..='z' | 'A'..='Z' | '0'..='9'))
+}
+
 fn write_cargo_toml_header(w: &mut impl std::io::Write, name: &str) -> std::io::Result<()> {
     writeln!(
         w,
@@ -87,8 +93,15 @@ pub fn write_main_rs<'a>(
     writeln!(w, "fn main() {{")?;
 
     for binary in intrinsics {
+        if !is_rust_identifier(binary) {
+            return Err(std::io::Error::new(
+                std::io::ErrorKind::InvalidInput,
+                format!("invalid Rust identifier: {binary:?}"),
+            ));
+        }
+
         writeln!(w, "    println!(\"{INTRINSIC_DELIMITER}\");")?;
-        writeln!(w, "    println!(\"{binary}\");")?;
+        writeln!(w, "    println!({binary:?});")?;
         writeln!(w, "    run_{binary}();\n")?;
     }
```