# cargo directive injection via library filename

## Classification

Medium severity vulnerability: Cargo build-script directive injection through an attacker-controlled environment variable.

Confidence: certain.

## Affected Locations

`library/profiler_builtins/build.rs:17`

## Summary

`LLVM_PROFILER_RT_LIB` is accepted during the profiler runtime build, converted to a `PathBuf`, reduced to its final filename component, and printed directly into a Cargo build-script directive:

```rust
println!("cargo::rustc-link-lib=static:+verbatim={}", lib.to_str().unwrap());
```

Cargo parses build-script stdout line-by-line. If the filename contains `\n` or `\r\n`, the intended `cargo::rustc-link-lib` directive can be terminated and a new attacker-controlled `cargo::...` directive can be injected.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was manually reproduced and patched.

## Preconditions

- The attacker controls `LLVM_PROFILER_RT_LIB` during build.
- The build host permits a path final component containing a newline.
- The injected filename is valid UTF-8 because the code calls `lib.to_str().unwrap()`.

## Proof

The vulnerable path is reached before normal profiler runtime compilation:

1. `tracked_env_var("LLVM_PROFILER_RT_LIB")` reads attacker-controlled input.
2. The value is converted to `PathBuf`.
3. `rt.file_name()` extracts the final path component.
4. `lib.to_str().unwrap()` is printed directly inside `cargo::rustc-link-lib=static:+verbatim=...`.
5. The build script returns immediately afterward.

A dynamic reproduction used the committed `library/profiler_builtins/build.rs` as a build script in a minimal crate with:

```sh
LLVM_PROFILER_RT_LIB=$'/tmp/libdoesnotmatter.a\ncargo::rustc-env=INJECTED=owned'
```

Cargo consumed the injected directive:

```text
cargo::rustc-env=INJECTED=owned
```

The compiled program then printed:

```text
injected=owned
```

This confirms arbitrary Cargo directive injection through the library filename.

## Why This Is A Real Bug

Cargo build scripts communicate with Cargo through stdout directives. Each line beginning with `cargo::` is interpreted as a distinct directive.

Because the library filename is embedded in a directive without rejecting line breaks, an attacker-controlled filename can escape the intended `rustc-link-lib` value and inject additional directives such as `cargo::rustc-env`, `cargo::rustc-link-arg`, or other build-affecting instructions.

The vulnerable branch returns immediately after printing the directive, so the injected directive is processed as part of normal build-script execution.

## Fix Requirement

Reject or safely encode carriage returns and line feeds before printing attacker-controlled data into any `cargo::...` build-script directive.

For this path, the required fix is to reject `\n` and `\r` in the extracted library filename before printing `cargo::rustc-link-lib`.

## Patch Rationale

The patch converts the filename to `&str`, validates that it contains neither line-feed nor carriage-return characters, and only then prints the Cargo directive:

```rust
let lib = lib.to_str().unwrap();
assert!(!lib.contains('\n') && !lib.contains('\r'), "library filename must not contain newlines");
println!("cargo::rustc-link-lib=static:+verbatim={lib}");
```

Rejecting both `\n` and `\r` prevents Unix newline injection and CRLF-style directive splitting. The existing behavior for valid filenames is preserved.

## Residual Risk

None

## Patch

```diff
diff --git a/library/profiler_builtins/build.rs b/library/profiler_builtins/build.rs
index fc1a9ecc1ec..a01d614fac2 100644
--- a/library/profiler_builtins/build.rs
+++ b/library/profiler_builtins/build.rs
@@ -14,7 +14,9 @@ fn main() {
             if let Some(dir) = rt.parent() {
                 println!("cargo::rustc-link-search=native={}", dir.display());
             }
-            println!("cargo::rustc-link-lib=static:+verbatim={}", lib.to_str().unwrap());
+            let lib = lib.to_str().unwrap();
+            assert!(!lib.contains('\n') && !lib.contains('\r'), "library filename must not contain newlines");
+            println!("cargo::rustc-link-lib=static:+verbatim={lib}");
             return;
         }
     }
```