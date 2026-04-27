# Wrong Extended CPUID Max Check

## Classification

Logic error, medium severity. Confidence: certain.

## Affected Locations

`library/std_detect/src/detect/os/x86.rs:83`

## Summary

The x86 runtime feature detector reads `CPUID(0x8000_0000).EAX` as the maximum supported extended CPUID leaf, but then checks `extended_max_basic_leaf >= 1` before querying `CPUID(0x8000_0001)`. Since extended leaves are numbered from `0x8000_0000`, this guard is too weak and permits querying an unsupported extended leaf when the maximum is exactly `0x8000_0000`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

A CPU or virtual CPU reports:

```text
CPUID(0x8000_0000).EAX == 0x8000_0000
```

## Proof

`detect_features()` calls `__cpuid(0x8000_0000_u32)` and stores `EAX` in `extended_max_basic_leaf`.

The original code then used:

```rust
let extended_proc_info_ecx = if extended_max_basic_leaf >= 1 {
    let CpuidResult { ecx, .. } = __cpuid(0x8000_0001_u32);
    ecx
} else {
    0
};
```

For `extended_max_basic_leaf == 0x8000_0000`, the condition `extended_max_basic_leaf >= 1` is true, so the detector queries `CPUID(0x8000_0001)` even though that leaf is not supported.

The returned `ECX` value is not discarded. It feeds feature detection for:

- `Feature::lzcnt` at `library/std_detect/src/detect/os/x86.rs:146`
- AMD/Hygon-only `Feature::sse4a`, `Feature::tbm`, and `Feature::xop` at `library/std_detect/src/detect/os/x86.rs:160`

The detector is reachable through the runtime feature cache: `library/std_detect/src/detect/cache.rs:202` invokes detection on first feature test via `detect_and_initialize()` at `library/std_detect/src/detect/cache.rs:177`.

## Why This Is A Real Bug

`CPUID(0x8000_0000).EAX` defines the highest supported extended CPUID function. A value of `0x8000_0000` means `0x8000_0001` is outside the supported range.

Querying an unsupported CPUID leaf can return unrelated or invalid register contents depending on CPU or hypervisor behavior. Because the detector consumes `ECX` from that unsupported query as feature bits, Rust may falsely report CPU features that were not actually enumerated, potentially causing runtime dispatch to select code paths requiring unsupported instructions.

## Fix Requirement

Only query `CPUID(0x8000_0001)` when:

```rust
extended_max_basic_leaf >= 0x8000_0001
```

Otherwise, treat the extended processor info feature word as zero.

## Patch Rationale

The patch changes the guard from a generic nonzero/basic-style comparison to the actual extended leaf number required by the subsequent CPUID call.

This preserves behavior for CPUs that support `0x8000_0001` and prevents unsupported-leaf reads for CPUs or VMs that only support `0x8000_0000`.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std_detect/src/detect/os/x86.rs b/library/std_detect/src/detect/os/x86.rs
index b24ef6a37ef..d603d9d0173 100644
--- a/library/std_detect/src/detect/os/x86.rs
+++ b/library/std_detect/src/detect/os/x86.rs
@@ -80,7 +80,7 @@ pub(crate) fn detect_features() -> cache::Initializer {
 
     // EAX = 0x8000_0001, ECX=0: Queries "Extended Processor Info and Feature
     // Bits"
-    let extended_proc_info_ecx = if extended_max_basic_leaf >= 1 {
+    let extended_proc_info_ecx = if extended_max_basic_leaf >= 0x8000_0001 {
         let CpuidResult { ecx, .. } = __cpuid(0x8000_0001_u32);
         ecx
     } else {
```