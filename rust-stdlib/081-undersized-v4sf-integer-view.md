# Undersized V4SF Integer View

## Classification

Invariant violation, medium severity, confirmed with certainty.

## Affected Locations

- `library/stdarch/crates/stdarch-gen-loongarch/src/main.rs:766`

## Summary

The generated C test helper declares `union v4sf` with `uint32_t i32[2]`, but the generator emits C code that reads `i32[0]` through `i32[3]` for `V4SF` operands. This creates out-of-bounds reads in generated C tests whenever a `V4SF` input is used.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- The LoongArch stdarch generator emits test data for a `V4SF` operand.
- A spec entry contains a `V4SF` input type.
- The generated C test producer is compiled or executed.

## Proof

`union v4sf` is declared with only two `uint32_t` integer elements:

```c
union v4sf
{
    __m128 v;
    int64_t i64[2];
    uint32_t i32[2];
    float f32[4];
};
```

The `V4SF` branch in `type_to_va` initializes four `f32` lanes and then emits a `printf` argument list that reads four `i32` lanes:

```c
{v}.i32[0], {v}.i32[1], {v}.i32[2], {v}.i32[3]
```

`gen_test_body` calls `type_to_va` for generated input operands, so any spec entry with a `V4SF` input reaches this access pattern.

The reproducer confirmed practical reachability through `library/stdarch/crates/stdarch-gen-loongarch/lsx.spec:1609`, where `lsx_vfadd_s` has `data-types = V4SF, V4SF, V4SF`.

A minimal C reproduction matching the committed union and access pattern produced compiler diagnostics for indexes 2 and 3 past `uint32_t[2]`, and UBSan reported runtime out-of-bounds errors for both reads.

## Why This Is A Real Bug

The union explicitly declares `i32` with length 2, so `i32[2]` and `i32[3]` are outside the declared array bounds. The generator emits those accesses for reachable `V4SF` test inputs, causing undefined behavior in the generated C test producer. This can miscompile, fail under sanitizers, or produce incorrect Rust test vectors.

## Fix Requirement

`union v4sf` must provide valid storage for all four 32-bit lanes read by the `V4SF` generator path, or the generator must stop reading through an undersized integer view.

## Patch Rationale

The patch changes `union v4sf` from `uint32_t i32[2]` to `uint32_t i32[4]`. This matches the existing `float f32[4]` lane count, matches the `V4SF` generator’s four-lane output, and keeps the integer bit-pattern printing behavior intact.

## Residual Risk

None

## Patch

```diff
diff --git a/library/stdarch/crates/stdarch-gen-loongarch/src/main.rs b/library/stdarch/crates/stdarch-gen-loongarch/src/main.rs
index 3a946a12d66..e3d4f628c86 100644
--- a/library/stdarch/crates/stdarch-gen-loongarch/src/main.rs
+++ b/library/stdarch/crates/stdarch-gen-loongarch/src/main.rs
@@ -761,7 +761,7 @@ union v4sf
 {{
     __m128 v;
     int64_t i64[2];
-    uint32_t i32[2];
+    uint32_t i32[4];
     float f32[4];
 }};
```