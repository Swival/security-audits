# Unchecked Firmware Timestamp Frequency

## Classification

Validation gap, medium severity.

## Affected Locations

`library/std/src/sys/time/uefi.rs:163`

## Summary

The UEFI `Instant::now()` timestamp protocol path trusted the firmware-reported timestamp frequency after `get_properties` returned success. If firmware reported `frequency = 0`, the value was passed as the denominator to `mul_div_u64`, causing division by zero before the fallback timing paths could run.

## Provenance

Confirmed from the supplied affected source, reproducer summary, and patch.

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- UEFI target.
- A UEFI Timestamp Protocol handle is available.
- The protocol implementation returns success from `get_properties`.
- The returned `timestamp::Properties` contains `frequency = 0`.
- A Rust UEFI application calls `Instant::now()`.

## Proof

`Instant::now()` first calls `instant_internal::timestamp_protocol()`.

Inside `timestamp_protocol()`, `try_handle()` opens each firmware-provided timestamp protocol handle and calls:

```rust
let r = unsafe { ((*protocol.as_ptr()).get_properties)(properties.as_mut_ptr()) };
if r.is_error() {
    return None;
}

let freq = unsafe { properties.assume_init().frequency };
let ts = unsafe { ((*protocol.as_ptr()).get_timestamp)() };
Some(mul_div_u64(ts, NS_PER_SEC, freq))
```

The only validation after `get_properties` is the error-status check. A successful status with `frequency = 0` reaches:

```rust
mul_div_u64(ts, NS_PER_SEC, freq)
```

The reproducer confirmed that `mul_div_u64` immediately performs division and modulo by the denominator in `library/std/src/sys/helpers/mod.rs:24`. Therefore `freq == 0` triggers division by zero.

Because the failure occurs inside `timestamp_protocol()` before it returns `None`, `Instant::now()` does not reach `platform_specific()` or the final fallback path. On UEFI targets with aborting panic behavior, this can abort the application.

## Why This Is A Real Bug

The timestamp frequency is firmware-controlled input. The code validated only the firmware call status, not the semantic validity of the returned properties. A zero frequency is invalid as a divisor and causes deterministic invalid division behavior when any Rust UEFI application calls `Instant::now()` through this path.

This is not a theoretical edge case: the reproduced trigger is a Timestamp Protocol implementation whose `get_properties` succeeds while writing `frequency = 0`.

## Fix Requirement

Reject zero firmware-reported timestamp frequency before calling `mul_div_u64`. The timestamp protocol handle should be treated as unusable and `try_handle()` should return `None`, allowing other handles or fallback timing implementations to be attempted.

## Patch Rationale

The patch adds a direct guard immediately after reading `properties.frequency`:

```rust
if freq == 0 {
    return None;
}
```

This is the narrowest correct fix because:

- It validates the exact untrusted value used as a divisor.
- It preserves existing behavior for valid nonzero frequencies.
- It avoids calling `get_timestamp` for an unusable protocol instance.
- It allows `timestamp_protocol()` to continue to other handles or return `None` so `Instant::now()` can attempt fallback timing sources.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/time/uefi.rs b/library/std/src/sys/time/uefi.rs
index 5a7eab9031e..ace1a4d3d18 100644
--- a/library/std/src/sys/time/uefi.rs
+++ b/library/std/src/sys/time/uefi.rs
@@ -160,6 +160,9 @@ fn try_handle(handle: NonNull<crate::ffi::c_void>) -> Option<u64> {
             }
 
             let freq = unsafe { properties.assume_init().frequency };
+            if freq == 0 {
+                return None;
+            }
             let ts = unsafe { ((*protocol.as_ptr()).get_timestamp)() };
             Some(mul_div_u64(ts, NS_PER_SEC, freq))
         }
```