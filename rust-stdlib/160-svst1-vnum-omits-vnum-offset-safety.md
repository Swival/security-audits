# svst1_vnum omits vnum offset safety

## Classification

Medium severity vulnerability: incomplete unsafe API safety contract for generated public AArch64 SVE intrinsics.

Confidence: certain.

## Affected Locations

`library/stdarch/crates/stdarch-gen-arm/spec/sve/aarch64.spec.yml:1721`

`library/stdarch/crates/stdarch-gen-arm/spec/sve/aarch64.spec.yml:3352`

Generated impact was reproduced in `library/stdarch/crates/core_arch/src/aarch64/sve/generated.rs:37930`.

## Summary

`svst1_vnum[_{type}]` computes an internal pointer with `base.offset(svcnt{size_literal}() as isize * vnum as isize)`, but its spec declared only `pointer_offset: predicated`.

That safety marker omits the additional `vnum`-scaled offset requirement. As a result, generated unsafe docs can tell callers to uphold the non-vnum pointer contract while the wrapper performs a stricter `pointer::offset` operation internally.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced against the generated SVE output and patched in the source spec.

## Preconditions

A caller uses generated `svst1_vnum_*` with a nonzero `vnum`.

## Proof

The affected spec entry accepts `vnum: i64` and composes the store by calling `svst1_{type}` with:

```yaml
MethodCall:
  - $base
  - offset
  - - Multiply:
        - CastAs: [{ FnCall: ["svcnt{size_literal}", []] }, isize]
        - CastAs: [$vnum, isize]
```

The vulnerable entry declared:

```yaml
safety:
  unsafe:
    - pointer_offset: predicated
    - dereference: predicated
```

Neighboring vnum load/store/prefetch APIs use `pointer_offset_vnum`, including `svld1_vnum`, `svst1{size_literal[1]}_vnum`, and `svprf{size_literal}_vnum`.

The generated `svst1_vnum_*` docs were reproduced without the `vnum`/VL-scaled pointer warning, while neighboring vnum APIs generated the expected warning.

## Why This Is A Real Bug

Rust callers rely on unsafe function documentation to know which obligations must be upheld.

For `svst1_vnum_*`, the wrapper itself performs `base.offset(VL * vnum)`. `pointer::offset` has strict in-allocation and overflow/provenance requirements. If the scaled offset leaves the allocation, or otherwise violates `offset` rules, undefined behavior can occur inside the intrinsic wrapper before or during the store address calculation.

Because the generated contract omitted the actual scaled-offset requirement, a caller could satisfy the documented `pointer_offset` and `dereference` obligations but still invoke UB through the wrapper’s hidden `vnum` offset computation.

## Fix Requirement

Change the `svst1_vnum[_{type}]` safety marker from `pointer_offset` to `pointer_offset_vnum`.

## Patch Rationale

The implementation already uses a `vnum`-scaled offset. `pointer_offset_vnum` is the matching safety marker used by equivalent vnum APIs and causes generated unsafe docs to state the correct caller obligation.

The patch changes only the safety metadata for `svst1_vnum[_{type}]`; it does not alter code generation semantics for the intrinsic body.

## Residual Risk

None

## Patch

```diff
diff --git a/library/stdarch/crates/stdarch-gen-arm/spec/sve/aarch64.spec.yml b/library/stdarch/crates/stdarch-gen-arm/spec/sve/aarch64.spec.yml
index 383e50b7cc7..4195059b7e0 100644
--- a/library/stdarch/crates/stdarch-gen-arm/spec/sve/aarch64.spec.yml
+++ b/library/stdarch/crates/stdarch-gen-arm/spec/sve/aarch64.spec.yml
@@ -3352,7 +3352,7 @@ intrinsics:
     doc: Non-truncating store
     safety:
       unsafe:
-        - pointer_offset: predicated
+        - pointer_offset_vnum: predicated
         - dereference: predicated
     arguments:
       ["pg: {predicate}", "base: *mut {type}", "vnum: i64", "data: {sve_type}"]
```