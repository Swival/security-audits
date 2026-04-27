# Invalid Minute Accepted

## Classification

Validation gap, medium severity, confidence: certain.

## Affected Locations

- `library/std/src/sys/pal/uefi/system_time.rs:39`

## Summary

`from_uefi` accepts `Time.minute == 60` even though valid UEFI minute values are `0..=59`. The accepted invalid value is later multiplied by 60 seconds, silently normalizing `00:60:00` into `01:00:00` and allowing invalid firmware or file timestamps to be treated as valid times.

## Provenance

Reproduced and patched from a verified scanner finding reported by Swival Security Scanner: https://swival.dev

## Preconditions

- UEFI `RuntimeServices.get_time` returns a `Time` value with `minute == 60`.
- Or another UEFI timestamp conversion path passes a `Time` value with `minute == 60` to `SystemTime::from_uefi`.

## Proof

`system_time::now()` obtains firmware time through `RuntimeServices.get_time`, writes it into `t`, and returns it when the status is not an error.

`SystemTime::now()` then calls `SystemTime::from_uefi(...).expect(...)`.

Inside `from_uefi`, validation rejects invalid seconds with:

```rust
t.second < 60
```

but accepts an invalid minute value with:

```rust
t.minute <= 60
```

The accepted value then propagates into epoch conversion:

```rust
+ (t.minute as u64) * SECS_IN_MINUTE
```

Therefore `minute == 60` becomes `3600` seconds and is normalized as an additional hour instead of being rejected. For example, `00:60:00` becomes equivalent to `01:00:00`, and `23:60:00` rolls into the next day.

The same conversion is reachable from file timestamp handling through `SystemTime::from_uefi` at `library/std/src/sys/fs/uefi.rs:886`.

## Why This Is A Real Bug

UEFI minute values are bounded to `0..=59`. The code already enforces this convention for seconds with `< 60`, but the minute check uses `<= 60`, creating an off-by-one validation error.

Because the value is not rejected and is instead used in arithmetic, the bug changes observable behavior: invalid timestamps are accepted and normalized into different valid instants. This can affect system time conversion and file timestamp conversion.

## Fix Requirement

Change minute validation from:

```rust
t.minute <= 60
```

to:

```rust
t.minute < 60
```

## Patch Rationale

The patch aligns minute validation with the valid UEFI range and with the existing second validation. It prevents `minute == 60` from reaching `localtime_epoch` arithmetic, so invalid timestamps are rejected by returning `None` instead of being silently normalized.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/pal/uefi/system_time.rs b/library/std/src/sys/pal/uefi/system_time.rs
index 557a49b27c2..9dfb9f75050 100644
--- a/library/std/src/sys/pal/uefi/system_time.rs
+++ b/library/std/src/sys/pal/uefi/system_time.rs
@@ -36,7 +36,7 @@ pub(crate) const fn from_uefi(t: &Time) -> Option<Duration> {
         && t.day <= 31
         && t.day != 0
         && t.second < 60
-        && t.minute <= 60
+        && t.minute < 60
         && t.hour < 24
         && t.nanosecond < 1_000_000_000
         && ((t.timezone <= 1440 && t.timezone >= -1440)
```