# Unsanitized Argument Name In Generated Identifiers

## Classification

Validation gap, medium severity.

## Affected Locations

`library/stdarch/crates/intrinsic-test/src/common/argument.rs:38`

## Summary

`Argument::new` stored metadata-provided argument names unchanged, and `generate_name` formatted `self.name` directly into generated C++ and Rust identifiers. If intrinsic metadata supplied a non-identifier or code-bearing argument name, `intrinsic-test` emitted invalid or attacker-influenced generated source.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Intrinsic metadata can supply arbitrary argument names.
- `intrinsic-test` generates C++ or Rust source for an intrinsic containing such an argument.

## Proof

`Argument::new` assigned the raw `name` into `Argument.name`. Later, `generate_name` returned:

```rust
format!("{}_val", self.name)
```

That generated name flowed into declarations, loads, and function calls through call sites such as C argument-list generation, Rust argument-list generation, and value loading.

A reproduced x86 XML parameter used:

```xml
<parameter etype="UI32" type="unsigned int" varname="a); int injected; /*" />
```

Running `intrinsic-test --generate-only --target x86_64-unknown-linux-gnu` completed and emitted unsanitized generated C++ including:

```cpp
alignas(64) const uint32_t a); int injected; /*_val_vals[] = {
unsigned int a); int injected; /*_val = cast<unsigned int>(*(&a); int injected; /*_val_vals[i]));
auto __return_value = _mm_popcnt_u32(a); int injected; /*_val);
```

It also emitted unsanitized generated Rust including:

```rust
let a); int injected; /*_val = *(A); INT INJECTED; /*_u32_20.as_ptr().offset(i));
let __return_value = f(a); int injected; /*_val as _);
```

## Why This Is A Real Bug

The argument name crosses from metadata into generated source-code syntax without validation. The observed behavior reliably breaks generated source, and under the stated untrusted-metadata precondition, code-bearing names can alter emitted C++ or Rust source structure. This is not merely cosmetic because the raw metadata string is emitted in identifier positions used by declarations, loads, and function calls.

## Fix Requirement

Argument names used in generated identifiers must be validated or canonicalized before code generation so they only contain characters valid for C/Rust identifiers and do not allow syntax injection.

## Patch Rationale

The patch adds `sanitize_identifier`, which canonicalizes argument names by preserving ASCII alphabetic characters, underscores, and non-leading ASCII digits, while replacing all other characters with underscores.

`Argument::new` now stores the sanitized name:

```rust
name: sanitize_identifier(&name),
```

This centralizes the fix at construction time so existing consumers of `self.name`, `generate_name`, and `rust_vals_array_name` receive safe identifier material without needing every generation site to sanitize independently.

## Residual Risk

None

## Patch

```diff
diff --git a/library/stdarch/crates/intrinsic-test/src/common/argument.rs b/library/stdarch/crates/intrinsic-test/src/common/argument.rs
index 385cf32d3bf..0a607a73800 100644
--- a/library/stdarch/crates/intrinsic-test/src/common/argument.rs
+++ b/library/stdarch/crates/intrinsic-test/src/common/argument.rs
@@ -16,6 +16,20 @@ pub struct Argument<T: IntrinsicTypeDefinition> {
     pub constraint: Option<Constraint>,
 }
 
+fn sanitize_identifier(name: &str) -> String {
+    let mut sanitized = String::with_capacity(name.len());
+
+    for (i, c) in name.chars().enumerate() {
+        if c == '_' || c.is_ascii_alphabetic() || (i > 0 && c.is_ascii_digit()) {
+            sanitized.push(c);
+        } else {
+            sanitized.push('_');
+        }
+    }
+
+    sanitized
+}
+
 impl<T> Argument<T>
 where
     T: IntrinsicTypeDefinition,
@@ -23,7 +37,7 @@ impl<T> Argument<T>
     pub fn new(pos: usize, name: String, ty: T, constraint: Option<Constraint>) -> Self {
         Argument {
             pos,
-            name,
+            name: sanitize_identifier(&name),
             ty,
             constraint,
         }
```