# Absolute realtime timer underflows into huge sleep

## Classification
- Type: logic error
- Severity: high
- Confidence: certain

## Affected Locations
- `crates/wasi/src/p1.rs:1390`

## Summary
- `poll_oneoff` handles absolute realtime clock subscriptions by converting the guest deadline into a relative sleep.
- When the deadline is still in the future, the code subtracts in the wrong direction and computes `now_ns - timeout`.
- Because both values are `u64`, that underflows and becomes a massive relative duration, causing an effectively unbounded wait instead of a short future wakeup.

## Provenance
- Verified from the supplied reproducer and code-path analysis.
- Reference: https://swival.dev

## Preconditions
- A Wasm guest calls `poll_oneoff` with an absolute realtime clock subscription whose timeout is later than the current realtime clock value.

## Proof
- In `crates/wasi/src/p1.rs:1390`, guest-controlled `SubscriptionClock.timeout` reaches the absolute realtime branch in `poll_oneoff`.
- That branch reads the current realtime value and, when `now < timeout`, computes `now_ns - timeout` instead of `timeout - now_ns`.
- The wrapped `u64` is passed to `monotonic_clock::subscribe_duration` as a relative duration.
- A deadline 5 ms in the future therefore becomes `2^64 - 5_000_000` ns, roughly 584.9 years.
- Downstream, this value reaches `subscribe_to_duration`; if representable it schedules the huge sleep, and if not it degrades to `Deadline::Never` in `crates/wasi/src/p2/host/clocks.rs:71`.
- The sibling implementation in `crates/wasi-preview1-component-adapter/src/lib.rs:2149` confirms intended behavior by correctly computing `deadline - now`.

## Why This Is A Real Bug
- The affected path is directly reachable from the WASIp1 `poll_oneoff` import with guest-supplied clock subscriptions.
- The observed behavior violates WASI timer semantics: a near-future absolute realtime deadline should wake shortly, not block indefinitely.
- Release builds manifest the bug as a huge sleep or never-wake condition; overflow-checking builds may trap instead, which is still incorrect behavior from the same root cause.

## Fix Requirement
- For absolute realtime deadlines in the future, compute the remaining delay as `timeout - now_ns`.
- If the deadline has already passed, use a zero-duration wait.

## Patch Rationale
- The patch changes the future-deadline calculation in `crates/wasi/src/p1.rs` to subtract `now_ns` from `timeout`.
- This preserves existing behavior for already-expired deadlines while restoring correct relative-delay conversion for future absolute realtime timers.
- The fix aligns this implementation with the sibling adapter logic and removes the underflow source.

## Residual Risk
- None

## Patch
- Patched in `002-absolute-realtime-timer-underflows-into-huge-sleep.patch`.