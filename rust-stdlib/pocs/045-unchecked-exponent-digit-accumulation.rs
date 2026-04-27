// Bug: parse_hex in libm/src/math/support/hex_float.rs uses pexp.saturating_mul(10)
//      then unchecked `pexp += digit as u32`, so an exponent string above u32::MAX
//      panics in debug/wraps in release.
// Expected: pexp = pexp.saturating_add(digit as u32).
// Observed: a "0x1p4294967296" exponent path panics under overflow-checks and
//           wraps under release semantics.
// Build/run:
//   rustc -C overflow-checks=on  045-unchecked-exponent-digit-accumulation.rs -o /tmp/poc045_chk && /tmp/poc045_chk
//   rustc -C overflow-checks=off 045-unchecked-exponent-digit-accumulation.rs -o /tmp/poc045_rel && /tmp/poc045_rel

fn buggy_accumulate(exponent_digits: &[u8]) -> u32 {
    let mut pexp: u32 = 0;
    for &b in exponent_digits {
        let digit = (b - b'0') as u32;
        pexp = pexp.saturating_mul(10);
        pexp = pexp.wrapping_add(digit);
    }
    pexp
}

fn buggy_accumulate_checked_arith(exponent_digits: &[u8]) -> u32 {
    let mut pexp: u32 = 0;
    for &b in exponent_digits {
        let digit = (b - b'0') as u32;
        pexp = pexp.saturating_mul(10);
        pexp += digit;
    }
    pexp
}

fn main() {
    let digits = b"4294967296";
    let result = buggy_accumulate(digits);
    println!("digits={} wrapped_pexp={}", std::str::from_utf8(digits).unwrap(), result);
    assert!(result < 4_294_967_290, "unchecked add wrapped past u32::MAX");
    println!("BUG TRIGGERED (release): exponent accumulator wrapped to {result}");

    let panicked = std::panic::catch_unwind(|| buggy_accumulate_checked_arith(digits)).is_err();
    if cfg!(debug_assertions) {
        assert!(panicked, "debug build must panic at the unchecked add");
        println!("BUG TRIGGERED (debug): unchecked += panicked as documented");
    } else {
        println!("release build: panic-form requires overflow-checks=on (panicked={panicked})");
    }
}
