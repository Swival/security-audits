// Bug: parse_hex grows the i32 `exp` by 4 for each significant hex digit after the
//      128-bit `sig` is full, without checked_add. >536M significant hex digits
//      overflow i32: panic in checked builds, wraps to i32::MIN in release.
// Expected: checked_add(4) returning HexFloatParseError("the value is too huge").
// Observed: PoC drives the same arithmetic and demonstrates wrap and panic forms.
// Build/run:
//   rustc -C overflow-checks=off 046-unchecked-mantissa-exponent-growth.rs -o /tmp/poc046_rel && /tmp/poc046_rel
//   rustc -C overflow-checks=on  046-unchecked-mantissa-exponent-growth.rs -o /tmp/poc046_chk && /tmp/poc046_chk

fn buggy_advance_exp(start: i32, extra_significant_digits: u64) -> i32 {
    let mut exp = start;
    let mut i: u64 = 0;
    while i < extra_significant_digits {
        exp = exp.wrapping_add(4);
        i += 1;
    }
    exp
}

fn buggy_advance_exp_checked_arith(start: i32, extra: u64) -> i32 {
    let mut exp = start;
    let mut i: u64 = 0;
    while i < extra {
        exp += 4;
        i += 1;
    }
    exp
}

fn main() {
    let start = 2_147_483_644i32;
    let extra: u64 = 1;

    let exp = buggy_advance_exp(start, extra);
    println!("start={start} extra_digits={extra} wrapped_exp={exp}");
    assert_eq!(exp, i32::MIN, "wrapping add 4 must reach i32::MIN");
    println!("BUG TRIGGERED (release): exp wrapped to i32::MIN");

    let panicked = std::panic::catch_unwind(|| buggy_advance_exp_checked_arith(start, extra)).is_err();
    if cfg!(debug_assertions) {
        assert!(panicked);
        println!("BUG TRIGGERED (debug): exp += 4 panicked");
    } else {
        println!("release: panic form requires overflow-checks=on (panicked={panicked})");
    }
}
