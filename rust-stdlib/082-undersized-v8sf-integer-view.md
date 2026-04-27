# undersized V8SF integer view

## Classification

Invariant violation, medium severity.

## Affected Locations

`library/stdarch/crates/stdarch-gen-loongarch/src/main.rs:774`

## Summary

The LoongArch stdarch test generator defines `union v8sf` with eight `float` lanes but only four `uint32_t` lanes. Generated C test code for `V8SF` initializes `f32[0..7]` and then prints `i32[0..7]`, so any generated `V8SF` test reads past the end of the `i32` array.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

A generated LoongArch test includes a `V8SF` operand or result.

## Proof

`V8SF` spec data reaches `gen_test_body`.

`type_to_ct("V8SF")` maps the type to `union v8sf`.

The generated union was:

```c
union v8sf
{
    __m256 v;
    int64_t i64[4];
    uint32_t i32[4];
    float f32[8];
};
```

`type_to_va("V8SF")` writes eight float lanes:

```c
v.f32[0] ... v.f32[7]
```

It then emits printf arguments reading eight integer lanes:

```c
v.i32[0] ... v.i32[7]
```

Because `i32` has only four elements, accesses `i32[4]` through `i32[7]` are out of bounds.

A minimal C reproduction using the same `uint32_t i32[4]` / `float f32[8]` union triggers Clang UBSan:

```text
runtime error: index 7 out of bounds for type 'uint32_t[4]'
```

## Why This Is A Real Bug

The generator has a concrete reachable path from LASX `V8SF` spec entries to generated C code that performs out-of-bounds array access. This occurs before Rust tests are emitted, making the generated C test producer invoke undefined behavior while printing upper lanes.

## Fix Requirement

`union v8sf` must expose an integer view with one `uint32_t` element for each `float f32` lane used by the generated printer.

## Patch Rationale

Changing `uint32_t i32[4]` to `uint32_t i32[8]` restores the invariant used by `type_to_va("V8SF")`: eight initialized `f32` lanes can be reinterpreted and printed through eight `i32` lanes. This matches the 256-bit `V8SF` layout and the generated `u32x8::new(...)` output.

## Residual Risk

None

## Patch

```diff
diff --git a/library/stdarch/crates/stdarch-gen-loongarch/src/main.rs b/library/stdarch/crates/stdarch-gen-loongarch/src/main.rs
index 3a946a12d66..e7310c53a1a 100644
--- a/library/stdarch/crates/stdarch-gen-loongarch/src/main.rs
+++ b/library/stdarch/crates/stdarch-gen-loongarch/src/main.rs
@@ -769,7 +769,7 @@ union v8sf
 {{
     __m256 v;
     int64_t i64[4];
-    uint32_t i32[4];
+    uint32_t i32[8];
     float f32[8];
 }};
```