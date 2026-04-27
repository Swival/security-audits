// Bug: isize CarryingMulAdd fallback widens through unsigned UDoubleSize,
//      so negative isize maps to a huge u128 and the widened multiply overflows.
// Expected: Signed double-width product of -1 * -1 == 1 (low), 0 (high).
// Observed: -1isize as u128 == u128::MAX; u128::MAX * u128::MAX overflows the widened type
//           and yields wrong bits.
// Build: rustc -C overflow-checks=off 182-unchecked-isize-widening-arithmetic-overflows.rs -o /tmp/poc182
// Run:   /tmp/poc182

fn carrying_mul_add_unsigned_widening(a: isize, b: isize, c: isize, d: isize) -> (usize, isize) {
    let wide = (a as u128)
        .wrapping_mul(b as u128)
        .wrapping_add(c as u128)
        .wrapping_add(d as u128);
    (wide as usize, (wide >> usize::BITS) as isize)
}

fn carrying_mul_add_signed_widening(a: isize, b: isize, c: isize, d: isize) -> (usize, isize) {
    let wide = (a as i128) * (b as i128) + (c as i128) + (d as i128);
    (wide as usize, (wide >> usize::BITS) as isize)
}

fn main() {
    let buggy = carrying_mul_add_unsigned_widening(-1, -1, 0, 0);
    let correct = carrying_mul_add_signed_widening(-1, -1, 0, 0);
    println!("buggy = {:?}", buggy);
    println!("correct = {:?}", correct);
    assert_eq!(correct, (1, 0));
    assert_ne!(buggy, correct, "fallback should differ from signed widening");
}
