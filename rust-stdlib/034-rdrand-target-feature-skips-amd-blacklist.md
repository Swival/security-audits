# RDRAND target feature skips AMD blacklist

## Classification

Logic error, medium severity.

## Affected Locations

`library/std/src/sys/random/uefi.rs:106`

## Summary

On x86 UEFI builds, `fill_bytes` falls back to `rdrand::fill_bytes` when `EFI_RNG_PROTOCOL` is unavailable or fails. The RDRAND fallback uses `RDRAND_GOOD`, initialized by `is_rdrand_good`.

Before the patch, `is_rdrand_good` placed both the CPUID availability check and the AMD pre-Zen vendor/family blacklist inside `#[cfg(not(target_feature = "rdrand"))]`. Building std with `target_feature="rdrand"` therefore removed the AMD blacklist entirely, allowing known-unreliable pre-Zen AMD RDRAND to be used if the runtime self-test passed.

## Provenance

Verified from the supplied source, reproduced by configuration analysis, and reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Target is x86 or x86_64 UEFI.
- std is built with `target_feature="rdrand"`.
- Runtime CPU is an AMD family before 17h / Zen.
- `EFI_RNG_PROTOCOL` is missing, unavailable, or returns an error.
- The one-time RDRAND self-test passes before the known AMD failure mode manifests.

## Proof

`fill_bytes` first tries `rng_protocol::fill_bytes(bytes)`. If that fails, x86/x86_64 builds call `rdrand::fill_bytes(bytes)`.

`rdrand::fill_bytes` only uses RDRAND when `*RDRAND_GOOD` is true. `RDRAND_GOOD` is initialized by `is_rdrand_good`.

In the affected source, the AMD blacklist is inside:

```rust
#[cfg(not(target_feature = "rdrand"))]
{
    ...
    if vendor_id == [*b"Auth", *b"enti", *b"cAMD"] {
        ...
        if family < 0x17 {
            return false;
        }
    }
    ...
}
```

When std is built with `target_feature="rdrand"`, this block is not compiled. The function then reaches only:

```rust
unsafe { self_test() }
```

The source comment states that AMD CPUs before family 17h sometimes fail to set CF when RDRAND fails after suspend. Because the blacklist is compiled out, those CPUs can pass the initial self-test and later provide unreliable RDRAND output through the UEFI random fallback path.

The reproducer also confirmed that `rdrand` is a stable Rust target feature and maps to LLVM `rdrnd`, making the build precondition practical.

## Why This Is A Real Bug

The blacklist exists because pre-Zen AMD RDRAND has a documented reliability failure mode. Its purpose is CPU-family exclusion, not instruction-availability detection.

Compiling with `target_feature="rdrand"` justifies omitting the CPUID RDRAND feature-bit check, because the binary assumes the instruction exists. It does not justify omitting the AMD vendor/family blacklist. The pre-Zen AMD failure is independent of whether the compiler target enables RDRAND.

As a result, a build-time target feature changes a runtime safety decision and permits use of a CPU RNG source that the same code explicitly rejects in non-`target_feature="rdrand"` builds.

## Fix Requirement

Run the AMD vendor/family blacklist regardless of `target_feature="rdrand"`.

Only the CPUID RDRAND feature-bit availability check should remain conditional on `#[cfg(not(target_feature = "rdrand"))]`.

## Patch Rationale

The patch moves CPUID leaf retrieval and AMD vendor/family evaluation outside the `#[cfg(not(target_feature = "rdrand"))]` block.

This preserves the intended behavior:

- Always reject AMD family `< 0x17`.
- Still require CPUID leaf 1 before using CPUID-derived data.
- Only skip the RDRAND feature-bit check when the binary is compiled with `target_feature="rdrand"`.
- Continue to run the existing self-test after runtime policy checks pass.

The patch therefore separates two distinct checks: CPU reliability blacklisting, which is always needed, and instruction availability probing, which is unnecessary when RDRAND is a required target feature.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/random/uefi.rs b/library/std/src/sys/random/uefi.rs
index f7a76008351..21b9bb82159 100644
--- a/library/std/src/sys/random/uefi.rs
+++ b/library/std/src/sys/random/uefi.rs
@@ -103,31 +103,31 @@ unsafe fn self_test() -> bool {
     }
 
     fn is_rdrand_good() -> bool {
-        #[cfg(not(target_feature = "rdrand"))]
-        {
-            // SAFETY: All Rust x86 targets are new enough to have CPUID, and we
-            // check that leaf 1 is supported before using it.
-            let cpuid0 = arch::__cpuid(0);
-            if cpuid0.eax < 1 {
+        // SAFETY: All Rust x86 targets are new enough to have CPUID, and we
+        // check that leaf 1 is supported before using it.
+        let cpuid0 = arch::__cpuid(0);
+        if cpuid0.eax < 1 {
+            return false;
+        }
+        let cpuid1 = arch::__cpuid(1);
+
+        let vendor_id =
+            [cpuid0.ebx.to_le_bytes(), cpuid0.edx.to_le_bytes(), cpuid0.ecx.to_le_bytes()];
+        if vendor_id == [*b"Auth", *b"enti", *b"cAMD"] {
+            let mut family = (cpuid1.eax >> 8) & 0xF;
+            if family == 0xF {
+                family += (cpuid1.eax >> 20) & 0xFF;
+            }
+            // AMD CPUs families before 17h (Zen) sometimes fail to set CF when
+            // RDRAND fails after suspend. Don't use RDRAND on those families.
+            // See https://bugzilla.redhat.com/show_bug.cgi?id=1150286
+            if family < 0x17 {
                 return false;
             }
-            let cpuid1 = arch::__cpuid(1);
-
-            let vendor_id =
-                [cpuid0.ebx.to_le_bytes(), cpuid0.edx.to_le_bytes(), cpuid0.ecx.to_le_bytes()];
-            if vendor_id == [*b"Auth", *b"enti", *b"cAMD"] {
-                let mut family = (cpuid1.eax >> 8) & 0xF;
-                if family == 0xF {
-                    family += (cpuid1.eax >> 20) & 0xFF;
-                }
-                // AMD CPUs families before 17h (Zen) sometimes fail to set CF when
-                // RDRAND fails after suspend. Don't use RDRAND on those families.
-                // See https://bugzilla.redhat.com/show_bug.cgi?id=1150286
-                if family < 0x17 {
-                    return false;
-                }
-            }
+        }
 
+        #[cfg(not(target_feature = "rdrand"))]
+        {
             const RDRAND_FLAG: u32 = 1 << 30;
             if cpuid1.ecx & RDRAND_FLAG == 0 {
                 return false;
```