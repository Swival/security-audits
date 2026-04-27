# svld3_vnum omits vnum offset safety

## Classification

Validation gap, medium severity.

Confidence: certain.

## Affected Locations

`library/stdarch/crates/stdarch-gen-arm/spec/sve/aarch64.spec.yml:1913`

Generated downstream evidence:

`library/stdarch/crates/core_arch/src/aarch64/sve/generated.rs:16536`

`library/stdarch/crates/core_arch/src/aarch64/sve/generated.rs:16543`

## Summary

`svld3_vnum` computes an address using `base.offset(svcnt{size_literal}() as isize * vnum as isize)`, but its safety metadata used `pointer_offset: predicated` instead of `pointer_offset_vnum: predicated`.

As a result, generated unsafe documentation omitted the vnum-specific obligation that `vnum` is scaled by SVE vector length `VL`, which is not known at compile time. Unsafe callers relying on the generated contract could under-account for the pointer offset and pass a `base`/`vnum` pair that forms an out-of-bounds pointer before the delegated load occurs.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced from the provided source and generated-code evidence.

## Preconditions

A caller relies on the generated safety documentation for `svld3_vnum`.

## Proof

`svld3_vnum` takes `vnum` as its third argument and composes the load by passing `base.offset(svcnt{size_literal}() as isize * vnum as isize)` into `svld3_{type}`.

The generated implementation contains the offset computation at:

`library/stdarch/crates/core_arch/src/aarch64/sve/generated.rs:16543`

The generated safety docs at:

`library/stdarch/crates/core_arch/src/aarch64/sve/generated.rs:16536`

omit the `pointer_offset_vnum` wording. That wording would add the warning from:

`library/stdarch/crates/stdarch-gen-arm/src/intrinsic.rs:853`

Specifically, `pointer_offset_vnum` documents that "`vnum` is scaled by the vector length, `VL`, which is not known at compile time".

The source cause is the `svld3_vnum` safety metadata using:

```yaml
- pointer_offset: predicated
```

instead of:

```yaml
- pointer_offset_vnum: predicated
```

## Why This Is A Real Bug

Rust pointer offset safety is part of the unsafe contract. The function computes a raw pointer offset before delegating to `svld3_*`, and that offset depends on runtime SVE vector length multiplied by `vnum`.

The existing generated contract documents only the predicated pointer-offset obligation, not the vnum-specific scaling obligation. This can mislead unsafe callers into validating only the visible active-lane access pattern while missing that `base.offset(VL * vnum)` itself must remain within the allocation.

This is source-grounded and reachable for `svld3_vnum`.

## Fix Requirement

Change `svld3_vnum` safety metadata from `pointer_offset: predicated` to `pointer_offset_vnum: predicated`.

## Patch Rationale

`svld3_vnum` has the same vnum-scaled pointer-offset shape as other vnum load/store intrinsics that use `pointer_offset_vnum`. Updating the safety key makes the generator emit the correct unsafe contract, including the runtime vector-length scaling warning.

The patch changes documentation/metadata only; it does not alter the generated address computation or intrinsic behavior.

## Residual Risk

None

## Patch

```diff
diff --git a/library/stdarch/crates/stdarch-gen-arm/spec/sve/aarch64.spec.yml b/library/stdarch/crates/stdarch-gen-arm/spec/sve/aarch64.spec.yml
index 383e50b7cc7..b0391e3e201 100644
--- a/library/stdarch/crates/stdarch-gen-arm/spec/sve/aarch64.spec.yml
+++ b/library/stdarch/crates/stdarch-gen-arm/spec/sve/aarch64.spec.yml
@@ -1913,7 +1913,7 @@ intrinsics:
     doc: Load three-element tuples into three vectors
     safety:
       unsafe:
-        - pointer_offset: predicated
+        - pointer_offset_vnum: predicated
         - dereference: predicated
     arguments: ["pg: {predicate}", "base: *{type}", "vnum: i64"]
     return_type: "{sve_type_x3}"
```