// Bug: cached_power computes a table index from gamma without bounds-checking,
// then indexes CACHED_POW10[idx as usize], panicking on out-of-range gamma.
// Expected: invalid gamma should be rejected with a clear contract assertion.
// Observed: panic from slice index out of bounds (DoS for callers of internal API).
// Build/run: rustc 099-unchecked-cached-power-index.rs -o /tmp/poc099 && /tmp/poc099

const CACHED_POW10_FIRST_E: i16 = -1087;
const CACHED_POW10_LAST_E: i16 = 1018;
const TABLE_LEN: usize = 81;

fn cached_power_buggy(_alpha: i16, gamma: i16) -> usize {
    let alpha_minus_e_minus_one_max: i32 = -64 + 1 - CACHED_POW10_LAST_E as i32;
    let offset = alpha_minus_e_minus_one_max;
    let range = (TABLE_LEN as i32) - 1;
    let domain = (CACHED_POW10_LAST_E - CACHED_POW10_FIRST_E) as i32;
    let idx = ((gamma as i32) - offset) * range / domain;
    idx as usize
}

fn main() {
    let table = [0u64; TABLE_LEN];
    let bad_gamma: i16 = -1114;
    let idx = cached_power_buggy(0, bad_gamma);
    println!("buggy cached_power gamma={} -> idx_as_usize={}", bad_gamma, idx);
    let panicked = std::panic::catch_unwind(|| {
        let _ = table[idx];
    })
    .is_err();
    assert!(panicked, "BUG: out-of-range index must panic against a sized table");
    println!("BUG TRIGGERED: out-of-range cached_power index panics on table access");
}
