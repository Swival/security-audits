# avx10_2 ignores avxvnniint16 presence

## Classification

Logic error, medium severity.

## Affected Locations

`library/std_detect/src/detect/os/x86.rs:301`

## Summary

`detect_features()` can report `Feature::avx10_2` even when `Feature::avxvnniint16` is absent. The local `avx10_2` prerequisite variable `avxvnniint16` was populated from CPUID EDX leaf 7 subleaf 1 bit 4, which enables `Feature::avxvnniint8`, instead of bit 10, which enables `Feature::avxvnniint16`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

CPUID/XCR0 must satisfy the surrounding AVX, AVX-512, and AVX10.1 reachability checks, and:

- `CPUID(0x24).EBX & 0xff >= 2`
- AVXVNNI present
- AVXIFMA present
- AVXVNNIINT8 present, CPUID leaf 7 subleaf 1 EDX bit 4 set
- AVXVNNIINT16 absent, CPUID leaf 7 subleaf 1 EDX bit 10 clear

The originally stated AVXNECONVERT condition is not required for this specific trigger because the `avx10_2` gate does not check it.

## Proof

In `detect_features()`:

```rust
let avxvnni = enable(extended_features_eax_leaf_1, 4, Feature::avxvnni);
let avxvnniint8 = enable(extended_features_eax_leaf_1, 23, Feature::avxifma);
let avxvnniint16 =
    enable(extended_features_edx_leaf_1, 4, Feature::avxvnniint8);
enable(extended_features_edx_leaf_1, 5, Feature::avxneconvert);
enable(extended_features_edx_leaf_1, 10, Feature::avxvnniint16);
```

The boolean named `avxvnniint16` receives the result of enabling `Feature::avxvnniint8` from EDX bit 4. The real `Feature::avxvnniint16` is enabled separately from EDX bit 10, but that result is discarded.

Later:

```rust
if avx10_version >= 2 && avxvnni && avxvnniint8 && avxvnniint16 {
    value.set(Feature::avx10_2 as u32);
}
```

Therefore, when EDX bit 4 is set and EDX bit 10 is clear, the local `avxvnniint16` gate is true while `Feature::avxvnniint16` remains unset. `Feature::avx10_2` is then set incorrectly.

## Why This Is A Real Bug

The adjacent comment states that AVX10.2 should only be reported when the unmasked prerequisite dot-product instruction features are available. The implementation violates that invariant by accepting AVXVNNIINT8 as the AVXVNNIINT16 prerequisite.

This over-reports `is_x86_feature_detected!("avx10.2")`. Runtime dispatch guarded by `avx10.2` can select code that assumes AVXVNNIINT16 availability and may execute unsupported instructions on CPUID exposures with AVX10.2 version reporting but without EDX bit 10, including under virtualization or future/variant hardware.

## Fix Requirement

Bind the `avxvnniint16` boolean used by the `avx10_2` gate to the `Feature::avxvnniint16` enable result from CPUID leaf 7 subleaf 1 EDX bit 10.

## Patch Rationale

The patch preserves feature enabling behavior while correcting the boolean used for the AVX10.2 prerequisite check:

- EDX bit 4 still enables `Feature::avxvnniint8`.
- EDX bit 10 still enables `Feature::avxvnniint16`.
- The local `avxvnniint16` variable now reflects EDX bit 10, matching its name and the `avx10_2` gate’s intended prerequisite.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std_detect/src/detect/os/x86.rs b/library/std_detect/src/detect/os/x86.rs
index b24ef6a37ef..64d1a282326 100644
--- a/library/std_detect/src/detect/os/x86.rs
+++ b/library/std_detect/src/detect/os/x86.rs
@@ -260,10 +260,10 @@ pub(crate) fn detect_features() -> cache::Initializer {
                     // "Short" versions of AVX512 instructions
                     let avxvnni = enable(extended_features_eax_leaf_1, 4, Feature::avxvnni);
                     let avxvnniint8 = enable(extended_features_eax_leaf_1, 23, Feature::avxifma);
-                    let avxvnniint16 =
-                        enable(extended_features_edx_leaf_1, 4, Feature::avxvnniint8);
+                    enable(extended_features_edx_leaf_1, 4, Feature::avxvnniint8);
                     enable(extended_features_edx_leaf_1, 5, Feature::avxneconvert);
-                    enable(extended_features_edx_leaf_1, 10, Feature::avxvnniint16);
+                    let avxvnniint16 =
+                        enable(extended_features_edx_leaf_1, 10, Feature::avxvnniint16);
 
                     enable(extended_features_eax_leaf_1, 0, Feature::sha512);
                     enable(extended_features_eax_leaf_1, 1, Feature::sm3);
```