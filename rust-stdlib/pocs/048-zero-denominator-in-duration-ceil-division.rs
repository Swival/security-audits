// Bug: Duration::div_duration_ceil performs u128::div_ceil by rhs.as_nanos()
//      without rejecting Duration::ZERO, so a zero divisor panics.
// Expected: explicit guard returning a defined panic at the API boundary.
// Observed: PoC mirrors the body and confirms the divide-by-zero panic.
// Build/run: rustc 048-zero-denominator-in-duration-ceil-division.rs -o /tmp/poc048 && /tmp/poc048
// Note: APIs are nightly-gated. PoC reproduces the arithmetic on stable.

const NANOS_PER_SEC: u128 = 1_000_000_000;

fn buggy_div_duration_ceil(self_nanos: u128, rhs_nanos: u128) -> u128 {
    self_nanos.div_ceil(rhs_nanos)
}

fn main() {
    let self_nanos = 1u128 * NANOS_PER_SEC;
    let rhs_nanos = 0u128;

    let panicked = std::panic::catch_unwind(|| buggy_div_duration_ceil(self_nanos, rhs_nanos)).is_err();
    assert!(panicked, "must panic on zero divisor");
    println!("BUG TRIGGERED: div_duration_ceil with Duration::ZERO panicked.");
}
