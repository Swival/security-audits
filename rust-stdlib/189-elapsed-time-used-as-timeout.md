# elapsed time used as timeout

## Classification

Logic error, medium severity.

## Affected Locations

`library/std/src/sys/pal/itron/time.rs:83`

## Summary

`with_tmos_strong` computes elapsed time since the start of a timed operation, but passes that elapsed value as the next timeout. For any positive `Duration`, the first call to the supplied timeout function receives `0`, causing immediate poll/timeout behavior instead of waiting for the requested remaining duration.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

`with_tmos_strong` is called with a positive `Duration`.

## Proof

In `library/std/src/sys/pal/itron/time.rs`, `ticks` is derived from `dur.as_micros()`, so a positive duration produces a positive timeout budget. The function then initializes:

```rust
let start = get_tim();
let mut elapsed = 0;
```

The loop condition `elapsed <= ticks` is true on the first iteration. However, the original code calls:

```rust
er = f(elapsed.min(abi::TMAX_RELTIM as abi::SYSTIM) as abi::TMO);
```

Because `elapsed` is `0` on the first iteration, the first timeout passed to `f` is `0`, not the positive remaining duration.

A concrete affected path is `library/std/src/sys/sync/condvar/itron.rs:98`, where the timeout is passed to `abi::tslp_tsk(tmo)`. Since `TMO` and `RELTIM` are microsecond timeout units, this converts a positive timed wait into an initial zero-duration poll.

## Why This Is A Real Bug

The function is documented to split a `Duration` into one or more API calls with timeout and to handle spurious wakeups. Passing elapsed time violates that contract: the timeout argument should represent the remaining wait budget, bounded by `TMAX_RELTIM`.

For positive durations, the old behavior always starts with a zero timeout. If that call returns `E_TMOUT`, subsequent iterations continue using elapsed time rather than remaining time, which can cause incorrect timeout behavior such as polling, busy looping on coarse clocks, or overshooting the requested timeout.

## Fix Requirement

Pass the remaining time budget to `f`, capped at `TMAX_RELTIM`:

```rust
(ticks - elapsed).min(abi::TMAX_RELTIM as abi::SYSTIM) as abi::TMO
```

The loop condition `elapsed <= ticks` guarantees `ticks - elapsed` does not underflow.

## Patch Rationale

The patch replaces elapsed-time timeout selection with remaining-time timeout selection:

```diff
-        er = f(elapsed.min(abi::TMAX_RELTIM as abi::SYSTIM) as abi::TMO);
+        er = f((ticks - elapsed).min(abi::TMAX_RELTIM as abi::SYSTIM) as abi::TMO);
```

This preserves the existing chunking behavior for large durations while making each API call wait for the correct remaining portion of the original timeout. It also preserves the existing handling of spurious wakeups by recomputing elapsed time after each timeout result.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/pal/itron/time.rs b/library/std/src/sys/pal/itron/time.rs
index ff3cffd2069..11c201b9ea9 100644
--- a/library/std/src/sys/pal/itron/time.rs
+++ b/library/std/src/sys/pal/itron/time.rs
@@ -80,7 +80,7 @@ pub fn with_tmos_strong(dur: Duration, mut f: impl FnMut(abi::TMO) -> abi::ER) -
     let mut elapsed = 0;
     let mut er = abi::E_TMOUT;
     while elapsed <= ticks {
-        er = f(elapsed.min(abi::TMAX_RELTIM as abi::SYSTIM) as abi::TMO);
+        er = f((ticks - elapsed).min(abi::TMAX_RELTIM as abi::SYSTIM) as abi::TMO);
         if er != abi::E_TMOUT {
             break;
         }
```