# unchecked CPUID 0x24 query

## Classification

Validation gap; medium severity.

## Affected Locations

`library/std_detect/src/detect/os/x86.rs:296`

## Summary

`detect_features()` queried CPUID leaf `0x24` after seeing AVX10.1, but did not first verify that the CPU reported support for basic leaf `0x24`. On CPUs or VM CPUID configurations where AVX10.1 is exposed but `max_basic_leaf < 0x24`, the unsupported query can return undefined or aliased data. Rust could then parse unrelated `EBX` low bits as an AVX10 version and incorrectly report `avx10.2`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- CPU or VM reports AVX10.1 via CPUID leaf `7`, subleaf `1`, `EDX` bit `19`.
- CPUID leaf `0` reports `max_basic_leaf < 0x24`.
- Runtime feature detection is invoked, for example through `is_x86_feature_detected!("avx10.2")`.
- The unsupported `__cpuid(0x24)` result contains or aliases data whose `EBX & 0xff` is at least `2`.
- AVX10.2 dependency gates `avxvnni`, `avxvnniint8`, and `avxvnniint16` are also satisfied.

## Proof

The code already records supported basic CPUID range from `__cpuid(0)` as `max_basic_leaf`, and validates other queried leaves such as `7` and `0xd` before use.

The AVX10.2 path instead did this:

```rust
let avx10_1 = enable(extended_features_edx_leaf_1, 19, Feature::avx10_1);
if avx10_1 {
    let CpuidResult { ebx, .. } = __cpuid(0x24);
    let avx10_version = ebx & 0xff;
```

A simulator matching the committed logic reproduced the propagation:

- `max_basic_leaf = 7`
- AVX10.1 set in CPUID leaf `7`, subleaf `1`, `EDX` bit `19`
- unsupported leaf `0x24` aliases to the highest basic leaf
- aliased leaf `7` `EBX` low byte is `0x02`
- buggy logic sets both `avx10.1` and `avx10.2`
- adding `max_basic_leaf >= 0x24` prevents `avx10.2`

## Why This Is A Real Bug

CPUID leaves are only valid when enumerated by the maximum supported leaf. Querying unsupported basic leaves is not a valid basis for feature detection. Because the returned data may be undefined or aliased, the code can over-report `avx10.2` on hardware or virtualized CPUID state that does not enumerate leaf `0x24` or AVX10.2.

The practical impact is unsafe runtime dispatch: Rust code may select AVX10.2 implementations and execute instructions unsupported by the actual CPU/VM, likely causing illegal-instruction crashes.

## Fix Requirement

Require `max_basic_leaf >= 0x24` before calling `__cpuid(0x24)` or deriving `avx10_version`.

## Patch Rationale

The patch applies the same CPUID leaf-range validation pattern already used elsewhere in `detect_features()`. AVX10.1 remains detected from the valid leaf `7`, subleaf `1` data, while AVX10.2 is only considered when leaf `0x24` is explicitly supported.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std_detect/src/detect/os/x86.rs b/library/std_detect/src/detect/os/x86.rs
index b24ef6a37ef..e736dcb1f43 100644
--- a/library/std_detect/src/detect/os/x86.rs
+++ b/library/std_detect/src/detect/os/x86.rs
@@ -294,7 +294,7 @@ pub(crate) fn detect_features() -> cache::Initializer {
                         enable(extended_features_eax_leaf_1, 5, Feature::avx512bf16);
 
                         let avx10_1 = enable(extended_features_edx_leaf_1, 19, Feature::avx10_1);
-                        if avx10_1 {
+                        if avx10_1 && max_basic_leaf >= 0x24 {
                             let CpuidResult { ebx, .. } = __cpuid(0x24);
                             let avx10_version = ebx & 0xff;
```