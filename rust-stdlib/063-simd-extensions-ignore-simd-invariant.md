# SIMD Extensions Ignore SIMD Invariant

## Classification

Invariant violation, medium severity.

## Affected Locations

`library/std_detect/src/detect/os/aarch64.rs:102`

Also affected before patch:

`library/std_detect/src/detect/os/aarch64.rs:105`

`library/std_detect/src/detect/os/aarch64.rs:106`

`library/std_detect/src/detect/os/aarch64.rs:107`

`library/std_detect/src/detect/os/aarch64.rs:108`

Reachable through OS register parsing paths including:

`library/std_detect/src/detect/os/freebsd/aarch64.rs:3`

`library/std_detect/src/detect/os/openbsd/aarch64.rs:34`

## Summary

The AArch64 system-register feature parser computed `Feature::asimd` using the full SIMD predicate, but enabled SIMD-dependent extensions using only the raw AdvSIMD register field. This allowed features such as `aes`, `sha2`, `rdm`, `dotprod`, and `sve` to be reported available even when `asimd` itself was disabled by the parser’s own prerequisite logic.

## Provenance

Verified from the supplied reproduced finding and patched source.

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- `aa64pfr0` is present.
- Floating-point support is absent or incompatible, or half-float compatibility fails.
- The raw AdvSIMD field is present.
- SIMD extension fields such as AES, SHA, RDM, dot product, or SVE are set.

## Proof

`parse_system_registers` derives:

```rust
let fp = bits_shift(aa64pfr0, 19, 16) < 0xF;
let fphp = bits_shift(aa64pfr0, 19, 16) >= 1;
let asimd = bits_shift(aa64pfr0, 23, 20) < 0xF;
let asimdhp = bits_shift(aa64pfr0, 23, 20) >= 1;
```

Before the patch, `Feature::asimd` was enabled only when:

```rust
fp && asimd && (!fphp | asimdhp)
```

However, SIMD extensions were enabled using only `asimd` plus their extension bits:

```rust
enable_feature(Feature::aes, asimd && bits_shift(aa64isar0, 7, 4) >= 2);
enable_feature(Feature::sha2, asimd && sha1 && sha2);
enable_feature(Feature::rdm, asimd && bits_shift(aa64isar0, 31, 28) >= 1);
enable_feature(Feature::dotprod, asimd && bits_shift(aa64isar0, 47, 44) >= 1);
enable_feature(Feature::sve, asimd && bits_shift(aa64pfr0, 35, 32) >= 1);
```

Thus, for a register image where `asimd == true` but `fp == false`, or where `fphp == true` and `asimdhp == false`, the parser disabled `Feature::asimd` while still enabling SIMD-dependent extension features.

## Why This Is A Real Bug

The source explicitly states that “SIMD extensions require SIMD support,” but the implementation did not enforce that invariant. Runtime detection could therefore report `is_aarch64_feature_detected!("aes")`, `"sha2"`, `"rdm"`, `"dotprod"`, or `"sve"` as true while reporting `"asimd"` as false.

Code dispatching on one of those extension feature checks could select SIMD-dependent instructions on a platform or OS-exposed register image that the same parser determined lacked valid SIMD support. That can violate the parser’s feature contract and may fault when the selected instructions execute.

## Fix Requirement

Gate all SIMD extension features on the computed SIMD predicate used for `Feature::asimd`, not on the raw AdvSIMD register field alone.

## Patch Rationale

The patch introduces:

```rust
let simd = fp && asimd && (!fphp | asimdhp);
```

It then uses `simd` both to enable `Feature::asimd` and to gate every SIMD-dependent extension:

```rust
enable_feature(Feature::asimd, simd);
enable_feature(Feature::aes, simd && bits_shift(aa64isar0, 7, 4) >= 2);
enable_feature(Feature::sha2, simd && sha1 && sha2);
enable_feature(Feature::rdm, simd && bits_shift(aa64isar0, 31, 28) >= 1);
enable_feature(Feature::dotprod, simd && bits_shift(aa64isar0, 47, 44) >= 1);
enable_feature(Feature::sve, simd && bits_shift(aa64pfr0, 35, 32) >= 1);
```

This preserves all existing extension-specific register checks while enforcing the invariant that no SIMD extension is reported unless SIMD itself is available.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std_detect/src/detect/os/aarch64.rs b/library/std_detect/src/detect/os/aarch64.rs
index 3232e435d52..08ec4efa04f 100644
--- a/library/std_detect/src/detect/os/aarch64.rs
+++ b/library/std_detect/src/detect/os/aarch64.rs
@@ -93,19 +93,20 @@ pub(crate) fn parse_system_registers(
         let fphp = bits_shift(aa64pfr0, 19, 16) >= 1;
         let asimd = bits_shift(aa64pfr0, 23, 20) < 0xF;
         let asimdhp = bits_shift(aa64pfr0, 23, 20) >= 1;
+        let simd = fp && asimd && (!fphp | asimdhp);
         enable_feature(Feature::fp, fp);
         enable_feature(Feature::fp16, fphp);
         // SIMD support requires float support - if half-floats are
         // supported, it also requires half-float support:
-        enable_feature(Feature::asimd, fp && asimd && (!fphp | asimdhp));
+        enable_feature(Feature::asimd, simd);
         // SIMD extensions require SIMD support:
-        enable_feature(Feature::aes, asimd && bits_shift(aa64isar0, 7, 4) >= 2);
+        enable_feature(Feature::aes, simd && bits_shift(aa64isar0, 7, 4) >= 2);
         let sha1 = bits_shift(aa64isar0, 11, 8) >= 1;
         let sha2 = bits_shift(aa64isar0, 15, 12) >= 1;
-        enable_feature(Feature::sha2, asimd && sha1 && sha2);
-        enable_feature(Feature::rdm, asimd && bits_shift(aa64isar0, 31, 28) >= 1);
-        enable_feature(Feature::dotprod, asimd && bits_shift(aa64isar0, 47, 44) >= 1);
-        enable_feature(Feature::sve, asimd && bits_shift(aa64pfr0, 35, 32) >= 1);
+        enable_feature(Feature::sha2, simd && sha1 && sha2);
+        enable_feature(Feature::rdm, simd && bits_shift(aa64isar0, 31, 28) >= 1);
+        enable_feature(Feature::dotprod, simd && bits_shift(aa64isar0, 47, 44) >= 1);
+        enable_feature(Feature::sve, simd && bits_shift(aa64pfr0, 35, 32) >= 1);
     }
 
     // ID_AA64ISAR1_EL1 - Instruction Set Attribute Register 1
```