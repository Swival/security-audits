// Bug: s390x vec_any_{lt,le,gt,ge} returned bitwise-NOT of an i32 0/1, yielding -1/-2.
// Expected: result of "any" comparison is normalized to 0 or 1.
// Observed: false comparison returns -2, which is nonzero, so `result != 0` is true.
// Build/run: rustc 093-any-comparisons-return-non-boolean-values.rs -o /tmp/poc093 && /tmp/poc093
// Target: s390x with vector feature; we model the i32 wrapper logic directly.

fn vec_all_ge_stub() -> i32 { 1 }

fn vec_any_lt_buggy() -> i32 {
    !vec_all_ge_stub()
}

fn vec_any_lt_fixed() -> i32 {
    i32::from(vec_all_ge_stub() == 0)
}

fn main() {
    let buggy = vec_any_lt_buggy();
    let fixed = vec_any_lt_fixed();
    println!("vec_any_lt with all lanes equal:");
    println!("  buggy result = {}, treated as bool: {}", buggy, buggy != 0);
    println!("  fixed result = {}, treated as bool: {}", fixed, fixed != 0);
    assert_eq!(buggy, -2);
    assert!(buggy != 0, "BUG: false comparison appears true under C-style boolean check");
    assert_eq!(fixed, 0);
}
