// Bug: Duration::div_duration_floor performs u128::div_floor by rhs.as_nanos()
//      without rejecting Duration::ZERO, so a zero divisor panics with
//      "attempt to divide by zero".
// Expected: explicit guard returning a defined panic at the API boundary.
// Observed: PoC mirrors the body and confirms the divide-by-zero panic.
// Build/run: rustc 047-zero-denominator-in-duration-floor-division.rs -o /tmp/poc047 && /tmp/poc047
// Note: APIs are nightly-gated behind `duration_integer_division`. This PoC
//       reproduces the exact arithmetic on stable to avoid the feature gate.

const NANOS_PER_SEC: u128 = 1_000_000_000;

fn buggy_div_duration_floor(self_nanos: u128, rhs_nanos: u128) -> u128 {
    self_nanos.div_euclid(rhs_nanos)
}

fn main() {
    let self_nanos = 1u128 * NANOS_PER_SEC;
    let rhs_nanos = 0u128;

    let panicked =
        std::panic::catch_unwind(|| buggy_div_duration_floor(self_nanos, rhs_nanos)).is_err();
    assert!(panicked, "must panic on zero divisor");
    println!("BUG TRIGGERED: div_duration_floor with Duration::ZERO panicked.");
}
