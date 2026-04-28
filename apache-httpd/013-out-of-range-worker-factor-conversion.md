# Out-of-Range Worker Factor Conversion

## Classification

Medium severity validation gap.

Confidence: certain.

## Affected Locations

`server/mpm/event/event.c:4114`

`server/mpm/event/event.c:4116`

`server/mpm/event/event.c:4119`

`server/mpm/event/event.c:4122`

`server/mpm/event/event.c:4149`

## Summary

`AsyncRequestWorkerFactor` accepts a floating-point configuration value, scales it by `WORKER_FACTOR_SCALE`, and stores the result in the unsigned integer global `worker_factor`. The parser rejected malformed text and non-positive values, but did not reject values whose scaled product exceeds `UINT_MAX`. A finite out-of-range `double` to `unsigned int` conversion is undefined behavior in C and is reachable during normal configuration parsing.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was independently reproduced and patched.

## Preconditions

`AsyncRequestWorkerFactor` is configured above `UINT_MAX / WORKER_FACTOR_SCALE`.

With `WORKER_FACTOR_SCALE` equal to `16`, a value such as `268435456` reaches the failing conversion on a 32-bit `unsigned int`.

## Proof

`AsyncRequestWorkerFactor` is registered as a global configuration directive and dispatches directly to `set_worker_factor`.

`set_worker_factor` parses the directive argument using `strtod`, then rejects only:

- trailing parse junk via `*endptr`
- values where `val <= 0`

Before the patch, it then executed:

```c
worker_factor = val * WORKER_FACTOR_SCALE;
```

For `val = 268435456`, the product is approximately `4294967296`, which is outside the range of a 32-bit `unsigned int`.

UBSan confirmed the assignment pattern with:

```text
runtime error: 4.29497e+09 is outside the range of representable values of type 'unsigned int'
```

## Why This Is A Real Bug

The path is reachable from ordinary configuration parsing during startup or reload. No later runtime condition is required.

C does not define the result of converting a finite floating-point value to an integer type when the value cannot be represented by that integer type. Because `worker_factor` is an `unsigned int`, assigning an oversized scaled `double` violates the destination representation bounds before subsequent connection limiting and pollset sizing logic uses the value.

## Fix Requirement

Reject `AsyncRequestWorkerFactor` values greater than `UINT_MAX / WORKER_FACTOR_SCALE` before computing and assigning the scaled value to `worker_factor`.

## Patch Rationale

The patch adds an explicit upper-bound check immediately after the existing positivity validation and before the floating-to-integer conversion:

```c
if (val > (double)UINT_MAX / WORKER_FACTOR_SCALE)
    return "AsyncRequestWorkerFactor argument is too large";
```

This preserves all valid positive inputs while preventing any accepted value from producing a scaled result outside the representable range of `unsigned int`.

## Residual Risk

None

## Patch

```diff
diff --git a/server/mpm/event/event.c b/server/mpm/event/event.c
index 050d823..dd990ed 100644
--- a/server/mpm/event/event.c
+++ b/server/mpm/event/event.c
@@ -4119,6 +4119,9 @@ static const char *set_worker_factor(cmd_parms * cmd, void *dummy,
     if (val <= 0)
         return "AsyncRequestWorkerFactor argument must be a positive number";
 
+    if (val > (double)UINT_MAX / WORKER_FACTOR_SCALE)
+        return "AsyncRequestWorkerFactor argument is too large";
+
     worker_factor = val * WORKER_FACTOR_SCALE;
     if (worker_factor < WORKER_FACTOR_SCALE) {
         worker_factor = WORKER_FACTOR_SCALE;
```