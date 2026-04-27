// Bug: PowerPC AltiVec vec_extract helper computes lane index with bitwise & instead of %.
// Expected: idx_in_vec(IDX=16) on a 16-lane u8 vector wraps to lane 0 (modulo doc).
// Observed: 16 & 16 == 16, which is out-of-bounds for simd_extract on a 16-lane vector.
// Build/run: rustc 091-out-of-range-simd-extract-index.rs -o /tmp/poc091 && /tmp/poc091

const fn idx_in_vec_buggy<T, const IDX: u32>() -> u32 {
    IDX & (16 / core::mem::size_of::<T>() as u32)
}

const fn idx_in_vec_fixed<T, const IDX: u32>() -> u32 {
    IDX % (16 / core::mem::size_of::<T>() as u32)
}

fn main() {
    let buggy_u8 = idx_in_vec_buggy::<u8, 16>();
    let buggy_i8 = idx_in_vec_buggy::<i8, 16>();
    let fixed_u8 = idx_in_vec_fixed::<u8, 16>();
    println!("vec_extract IDX=16 on 16-lane byte vector:");
    println!("  buggy<u8> = {}, buggy<i8> = {}, fixed<u8> = {}", buggy_u8, buggy_i8, fixed_u8);
    assert_eq!(buggy_u8, 16);
    assert_eq!(buggy_i8, 16);
    assert_eq!(fixed_u8, 0);
    assert!(buggy_u8 >= 16, "BUG: buggy helper feeds out-of-range lane to simd_extract");
}
