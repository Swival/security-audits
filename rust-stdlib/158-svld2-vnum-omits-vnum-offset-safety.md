# svld2_vnum omits vnum offset safety

## Classification

Validation gap, medium severity, confidence certain.

## Affected Locations

`library/stdarch/crates/stdarch-gen-arm/spec/sve/aarch64.spec.yml:1875`

## Summary

`svld2_vnum` computes its effective base pointer with `base.offset(svcnt{size_literal}() as isize * vnum as isize)` but declared only `pointer_offset` safety. That safety kind documents the unscaled predicated pointer offset, not the runtime vector-length-scaled `vnum` offset. As a result, the generated unsafe API contract omitted the required obligation that `base` must remain valid after applying the `vnum * VL` offset.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

A caller invokes `svld2_vnum` with a nonzero `vnum`.

## Proof

The spec entry for `svld2_vnum` accepts `vnum: i64` and composes the call by offsetting `base` before calling `svld2_{type}`:

```yaml
- name: svld2_vnum[_{type}]
  safety:
    unsafe:
      - pointer_offset: predicated
      - dereference: predicated
  arguments: ["pg: {predicate}", "base: *{type}", "vnum: i64"]
  compose:
    - FnCall:
        - "svld2_{type}"
        - - $pg
          - MethodCall:
              - $base
              - offset
              - - Multiply:
                    - CastAs: [{ FnCall: ["svcnt{size_literal}", []] }, isize]
                    - CastAs: [$vnum, isize]
```

The generated public wrapper therefore performs a Rust pointer offset by `svcnt{size_literal}() * vnum`. Adjacent vnum APIs such as `svld1_vnum` and `svld4_vnum` use `pointer_offset_vnum`, which generates the missing warning that `vnum` is scaled by the runtime vector length.

## Why This Is A Real Bug

The operation is reachable through committed generated public SVE intrinsics. An unsafe caller can satisfy the documented unshifted predicated load obligation while passing a nonzero `vnum` whose `VL`-scaled offset leaves the allocation or violates pointer provenance. The wrapper then performs `pointer::offset` with that invalid runtime-scaled distance and may issue an out-of-bounds load. This is an unsafe API contract/documentation gap, not safe-code memory corruption, but the contract is the mechanism callers rely on to uphold Rust safety requirements.

## Fix Requirement

Change `svld2_vnum` safety metadata from `pointer_offset` to `pointer_offset_vnum`.

## Patch Rationale

`pointer_offset_vnum` matches the implementation because the pointer adjustment is not a simple predicated offset; it is `vnum` multiplied by the runtime SVE vector length. This aligns `svld2_vnum` with adjacent vnum loads and causes generated safety docs/contracts to include the missing `vnum`/`VL` obligation.

## Residual Risk

None

## Patch

```diff
diff --git a/library/stdarch/crates/stdarch-gen-arm/spec/sve/aarch64.spec.yml b/library/stdarch/crates/stdarch-gen-arm/spec/sve/aarch64.spec.yml
index 383e50b7cc7..0a57e6ebfc1 100644
--- a/library/stdarch/crates/stdarch-gen-arm/spec/sve/aarch64.spec.yml
+++ b/library/stdarch/crates/stdarch-gen-arm/spec/sve/aarch64.spec.yml
@@ -1875,7 +1875,7 @@ intrinsics:
     doc: Load two-element tuples into two vectors
     safety:
       unsafe:
-        - pointer_offset: predicated
+        - pointer_offset_vnum: predicated
         - dereference: predicated
     arguments: ["pg: {predicate}", "base: *{type}", "vnum: i64"]
     return_type: "{sve_type_x2}"
```