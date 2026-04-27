# Nonexistent Dates Accepted

## Classification

Validation gap, medium severity. Confidence: certain.

## Affected Locations

`library/std/src/sys/pal/uefi/system_time.rs:36`

## Summary

`from_uefi` accepted impossible calendar dates because it only validated `day` as `1..=31`, regardless of month and leap year. A firmware-reported `Time` such as February 31 passed validation, entered date arithmetic, and produced a valid `Duration` for a nonexistent date instead of returning `None`.

## Provenance

Verified from the supplied source, reproducer summary, and patch. Originally identified by Swival Security Scanner: https://swival.dev

## Preconditions

UEFI `RuntimeServices::get_time` returns a `Time` value with an impossible day for its month, such as `2023-02-31`.

## Proof

`system_time::now()` obtains a `Time` from UEFI runtime services and returns it to callers.

`from_uefi` then validates:

```rust
t.month <= 12
&& t.month != 0
&& t.year >= 1900
&& t.year <= 9999
&& t.day <= 31
&& t.day != 0
```

This permits `Time { year: 2023, month: 2, day: 31, ... }`.

The accepted invalid date then flows into:

```rust
let days: u32 = y_adj * 365 + leap_days + month_days + (t.day as u32 - 1) - 2447065;
```

and returns:

```rust
Some(Duration::new(epoch, t.nanosecond))
```

Using the source formula, `2023-02-31 00:00:00 timezone 0` silently normalizes to the same duration as `2023-03-03 00:00:00 timezone 0`.

Reachability is practical through `SystemTime::now`, which calls firmware `get_time` through `system_time::now()` and then converts the value with `Self::from_uefi(...)` in `library/std/src/sys/time/uefi.rs:119`.

## Why This Is A Real Bug

The function is expected to reject invalid UEFI time values by returning `None`. It already rejects invalid months, years, hours, seconds, nanoseconds, and timezone values, but failed to reject month-specific invalid days.

This causes corrupt or nonconforming firmware time to be accepted as a plausible but wrong `SystemTime`. Time-based checks that depend on date correctness can then operate on a normalized date that was never reported by firmware.

## Fix Requirement

Validate `day` against the actual maximum day for the given month, including leap-year-specific February length.

## Patch Rationale

The patch computes `max_day` before the validation guard:

```rust
let max_day = match t.month {
    1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
    4 | 6 | 9 | 11 => 30,
    2 if t.year % 4 == 0 && (t.year % 100 != 0 || t.year % 400 == 0) => 29,
    2 => 28,
    _ => 0,
};
```

It then replaces the generic `t.day <= 31` check with:

```rust
t.day <= max_day
```

This preserves existing validation for valid dates while rejecting impossible dates such as April 31, February 29 in non-leap years, and February 30/31 in all years. Invalid months map to `max_day = 0`, so the existing guard still rejects them.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/pal/uefi/system_time.rs b/library/std/src/sys/pal/uefi/system_time.rs
index 557a49b27c2..5fb2f7a2e04 100644
--- a/library/std/src/sys/pal/uefi/system_time.rs
+++ b/library/std/src/sys/pal/uefi/system_time.rs
@@ -29,11 +29,19 @@ pub(crate) fn now() -> Time {
 /// The changes are to use 1900-01-01-00:00:00 with timezone -1440 as anchor instead of UNIX
 /// epoch used in the original algorithm.
 pub(crate) const fn from_uefi(t: &Time) -> Option<Duration> {
+    let max_day = match t.month {
+        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
+        4 | 6 | 9 | 11 => 30,
+        2 if t.year % 4 == 0 && (t.year % 100 != 0 || t.year % 400 == 0) => 29,
+        2 => 28,
+        _ => 0,
+    };
+
     if !(t.month <= 12
         && t.month != 0
         && t.year >= 1900
         && t.year <= 9999
-        && t.day <= 31
+        && t.day <= max_day
         && t.day != 0
         && t.second < 60
         && t.minute <= 60
```