# Unsupported Parameters Are Silently Omitted

## Classification

Validation gap, medium severity. Confidence: certain.

## Affected Locations

`library/stdarch/crates/stdarch-gen-hexagon/src/main.rs:337`

## Summary

`parse_prototype` silently dropped prototype parameters whose syntax did not match the supported parameter regex. The generator then used the truncated parameter list to emit LLVM extern declarations and public Rust wrappers, producing signatures that do not match the real C/LLVM ABI.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

A checked-in or future LLVM HVX header contains a C intrinsic prototype parameter using valid C syntax that is not accepted by the generator’s supported parameter pattern.

Example trigger:

```c
HVX_Vector *Rt
```

instead of:

```c
HVX_Vector* Rt
```

## Proof

`parse_prototype` splits the prototype parameter list, then applies:

```rust
let param_re = Regex::new(r"(\w+\*?)\s+(\w+)").unwrap();
```

Only parameters captured by this regex are appended to `params`.

Before the patch, if `param_re.captures(param)` failed, the loop continued without error. Therefore unsupported parameter syntax was omitted rather than rejected.

The reproduced case changed a prototype parameter from `HVX_Vector* Rs` to `HVX_Vector *Rs`. Generation still succeeded, but emitted a truncated extern and wrapper:

```rust
fn vgathermh(_: i32, _: i32, _: HvxVector) -> ();
```

and:

```rust
pub unsafe fn Q6_vgather_ARMVh(rt: i32, mu: i32, vv: HvxVector)
```

The required destination pointer parameter was omitted.

The truncated `params` vector flows into LLVM extern declaration generation at `library/stdarch/crates/stdarch-gen-hexagon/src/main.rs:1214` and wrapper signature/call generation at `library/stdarch/crates/stdarch-gen-hexagon/src/main.rs:1472`.

## Why This Is A Real Bug

The generator treats the LLVM HVX header as the source of truth for ABI-bearing declarations. Silently dropping an unmatched parameter converts a parse failure into generated Rust code with the wrong function arity and ABI.

This is not a harmless parse omission: the generated extern declaration and wrapper both become inconsistent with the underlying intrinsic signature. Calls through those wrappers can pass the wrong arguments to LLVM intrinsics and expose incorrect public APIs.

The current committed header was scanned and did not contain an existing single-line prototype parameter that triggers this exact omission, so the practical trigger is a future or changed checked-in header using unsupported-but-valid parameter syntax.

## Fix Requirement

Reject any prototype containing a parameter that does not match the supported parameter syntax. Parsing must fail closed instead of generating declarations from an incomplete parameter vector.

## Patch Rationale

The patch adds an `else` branch after the parameter regex capture attempt:

```rust
} else {
    return None; // Unsupported parameter syntax
}
```

This preserves existing behavior for supported parameters and unknown mapped types, while ensuring unmatched syntax causes `parse_prototype` to return `None`.

That prevents malformed or partially parsed prototypes from reaching extern and wrapper generation.

## Residual Risk

None

## Patch

```diff
diff --git a/library/stdarch/crates/stdarch-gen-hexagon/src/main.rs b/library/stdarch/crates/stdarch-gen-hexagon/src/main.rs
index 79837e2224e..d899313ff96 100644
--- a/library/stdarch/crates/stdarch-gen-hexagon/src/main.rs
+++ b/library/stdarch/crates/stdarch-gen-hexagon/src/main.rs
@@ -346,6 +346,8 @@ fn parse_prototype(prototype: &str) -> Option<(RustType, Vec<(String, RustType)>
                     } else {
                         return None; // Unknown type
                     }
+                } else {
+                    return None; // Unsupported parameter syntax
                 }
             }
         }
```