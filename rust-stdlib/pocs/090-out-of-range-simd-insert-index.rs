// Bug: PowerPC AltiVec vec_insert helper computes lane index with bitwise & instead of %.
// Expected: idx_in_vec(IDX=16) for 16-lane byte vector wraps to 0.
// Observed: 16 & 16 == 16, which is out of range for a 16-lane SIMD vector.
// Build/run: rustc 090-out-of-range-simd-insert-index.rs -o /tmp/poc090 && /tmp/poc090
// Target: PowerPC altivec; we model the const helper directly so it builds anywhere.

const fn idx_in_vec_buggy<T, const IDX: u32>() -> u32 {
    IDX & (16 / core::mem::size_of::<T>() as u32)
}

const fn idx_in_vec_fixed<T, const IDX: u32>() -> u32 {
    IDX % (16 / core::mem::size_of::<T>() as u32)
}

fn main() {
    let lane_count_byte: u32 = 16;
    let buggy = idx_in_vec_buggy::<u8, 16>();
    let fixed = idx_in_vec_fixed::<u8, 16>();
    println!("16-lane u8 vector, IDX=16:");
    println!("  buggy idx_in_vec = {} (must be < {})", buggy, lane_count_byte);
    println!("  fixed idx_in_vec = {} (must be < {})", fixed, lane_count_byte);
    assert_eq!(buggy, 16, "buggy helper produces out-of-range lane");
    assert!(buggy >= lane_count_byte, "buggy result reaches simd_insert as out-of-range");
    assert_eq!(fixed, 0, "fixed helper wraps modulo lane count");
    assert!(fixed < lane_count_byte, "fixed result is in range");
    println!("BUG TRIGGERED: buggy lane {} >= lane_count {}", buggy, lane_count_byte);
}
