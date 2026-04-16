# Leading Exponent Period Underflows Index

## Classification

Denial of service, low severity.

## Affected Locations

- `lib/std/zig/number_literal.zig:125`

## Summary

`parseNumberLiteral` can panic in safety-checked builds when parsing the two-byte input `e.`. The parser treats the leading `e` as an exponent marker, then the following `.` enters the period arm and subtracts `".e".len` from `i`. At that point `i == 1`, so `1 - 2` underflows `usize`, causing a Zig safety panic before the function can return a normal `Result`.

## Provenance

Reported and reproduced from Swival.dev Security Scanner analysis: https://swival.dev

Confidence: certain.

## Preconditions

- A process parses attacker-supplied numeric text with safety checks enabled.
- The attacker can provide the numeric text `e.` or equivalent input reaching `std.zig.parseNumberLiteral`.

## Proof

For input:

```text
e.
```

Execution proceeds as follows:

1. `parseNumberLiteral` starts with `i = 0` and decimal base.
2. At `i == 0`, byte `e` enters the `'e', 'E'` switch arm for base 10.
3. The parser sets:
   - `float = true`
   - `special = 'e'`
   - `exponent = true`
4. The loop continues to `i == 1`.
5. At `i == 1`, byte `.` enters the period arm.
6. Because `exponent == true`, the code executes:

```zig
const digit_index = i - ".e".len;
```

Here:

```zig
i == 1
".e".len == 2
```

So the expression is:

```zig
1 - 2
```

on `usize`.

With Zig safety checks enabled, this traps as integer overflow:

```text
panic: integer overflow
lib/std/zig/number_literal.zig:125:43: in parseNumberLiteral
    const digit_index = i - ".e".len;
```

A minimal reproducer is:

```zig
const std = @import("std");

pub fn main() void {
    const r = std.zig.parseNumberLiteral("e.");
    std.debug.print("{any}\n", .{r});
}
```

## Why This Is A Real Bug

The function is documented as:

```zig
/// Valid for any input.
pub fn parseNumberLiteral(bytes: []const u8) Result
```

Therefore malformed numeric text should produce a `Result.failure`, not abort the process.

The vulnerable path is reachable with the two-byte attacker-controlled input `e.`. In safety-checked builds, the unchecked unsigned subtraction panics before any error result is returned. A lower-privileged user able to submit numeric text to a parser using this function can terminate that parser process, producing a practical denial of service.

## Fix Requirement

The subtraction must only execute when `i >= ".e".len`, or the logic must otherwise avoid subtracting for a leading exponent marker.

## Patch Rationale

The patch adds a lower-bound guard before computing `i - ".e".len`:

```zig
if (exponent and i >= ".e".len) {
```

This preserves the existing look-behind behavior when enough bytes exist, while preventing unsigned underflow for short inputs such as `e.`.

For `e.`, the guarded block is skipped, allowing the parser to continue and return a normal failure result instead of panicking.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/std/zig/number_literal.zig b/lib/std/zig/number_literal.zig
index a4dc33eb91..f03567bb2f 100644
--- a/lib/std/zig/number_literal.zig
+++ b/lib/std/zig/number_literal.zig
@@ -121,7 +121,7 @@ pub fn parseNumberLiteral(bytes: []const u8) Result {
                 continue;
             },
             '.' => {
-                if (exponent) {
+                if (exponent and i >= ".e".len) {
                     const digit_index = i - ".e".len;
                     if (digit_index < bytes.len) {
                         switch (bytes[digit_index]) {
```