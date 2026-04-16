# u128 Float-Form Integer Intermediate i128 Overflow

## Classification

Denial of service, medium severity.

## Affected Locations

- `lib/std/json/static.zig:672`
- Root cause in `sliceToInt` at `lib/std/json/static.zig:783`

## Summary

`std.json` parsing of float-form integer tokens into `u128` performed a checked bounds validation against `u128`, but then converted the value through an intermediate `i128`. Rounded float-form values greater than `maxInt(i128)` and less than or equal to `maxInt(u128)` passed validation and then triggered a runtime safety panic during the intermediate `i128` conversion.

In services parsing attacker-controlled JSON into `u128` with runtime safety enabled, this allowed a remote denial of service via process abort.

## Provenance

Verified and reproduced from Swival.dev Security Scanner findings.

Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- A service parses attacker-controlled JSON.
- The target Zig type contains or is `u128`.
- Runtime safety is enabled, such as Debug or ReleaseSafe-style builds.
- The attacker supplies a float-form integer token or string accepted by the integer parser path.

## Proof

The affected path is:

1. `innerParse` handles `.int` types.
2. It obtains an attacker-controlled JSON number/string token.
3. It calls `sliceToInt(T, slice)`.
4. For non-integer-formatted numbers, `sliceToInt` parses the token as `f128`.
5. It verifies the float is rounded and within `std.math.minInt(T)` / `std.math.maxInt(T)`.
6. For `T = u128`, `2^127` is valid because it is within `u128`.
7. The old return expression then converted through `i128`:

```zig
return @as(T, @intCast(@as(i128, @intFromFloat(float))));
```

Reproducer:

```zig
const std = @import("std");

pub fn main() !void {
    const input = "170141183460469231731687303715884105728.0"; // 2^127
    const parsed = try std.json.parseFromSlice(u128, std.heap.page_allocator, input, .{});
    defer parsed.deinit();
}
```

Observed safety-enabled abort:

```text
panic: integer part of floating point value out of bounds
lib/std/json/static.zig:783:38:
    return @as(T, @intCast(@as(i128, @intFromFloat(float))));
```

## Why This Is A Real Bug

The parser explicitly accepts rounded float-form integer values within the destination type bounds. For `u128`, values in the range `[2^127, maxInt(u128)]` are valid destination values.

The implementation contradicted its own bounds check by forcing the already-validated value through `i128`, whose maximum is `2^127 - 1`. In safety-enabled builds this is not returned as `error.Overflow`; it panics and aborts the process. Since JSON input can be controlled by a remote peer in typical services, this is a reachable denial of service.

## Fix Requirement

After validating that the rounded `f128` value is within the destination integer type `T`, convert directly from float to `T`. Do not route the conversion through `i128`.

## Patch Rationale

The patch changes only the final conversion in `sliceToInt`:

```zig
return @as(T, @intFromFloat(float));
```

This preserves the existing behavior:

- non-rounded float-form numbers still return `error.InvalidNumber`;
- values outside `T` still return `error.Overflow`;
- valid values within `T`, including `u128` values above `maxInt(i128)`, are converted without an invalid intermediate narrowing step.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/std/json/static.zig b/lib/std/json/static.zig
index d177237842..291fa1789d 100644
--- a/lib/std/json/static.zig
+++ b/lib/std/json/static.zig
@@ -780,7 +780,7 @@ fn sliceToInt(comptime T: type, slice: []const u8) !T {
     const float = try std.fmt.parseFloat(f128, slice);
     if (@round(float) != float) return error.InvalidNumber;
     if (float > @as(f128, @floatFromInt(std.math.maxInt(T))) or float < @as(f128, @floatFromInt(std.math.minInt(T)))) return error.Overflow;
-    return @as(T, @intCast(@as(i128, @intFromFloat(float))));
+    return @as(T, @intFromFloat(float));
 }
 
 fn sliceToEnum(comptime T: type, slice: []const u8) !T {
```