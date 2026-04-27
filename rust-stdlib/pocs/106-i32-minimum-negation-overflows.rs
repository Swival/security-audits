// Bug: Hermit IsNegative for i32 uses -(*self), overflowing for i32::MIN.
// Target: x86_64-unknown-hermit (mirrored on host with overflow-checks).
// Expected: saturating_neg or checked_neg fallback.
// Observed: panic "attempt to negate with overflow" with checks; with no checks
//           wraps to i32::MIN and forwards a negative raw OS error.
// Build/run: rustc -C overflow-checks=on 106-i32-minimum-negation-overflows.rs \
//            -o /tmp/poc106 && /tmp/poc106

trait IsNegative {
    fn is_negative(&self) -> bool;
    fn negate(&self) -> i32;
}

impl IsNegative for i32 {
    fn is_negative(&self) -> bool { *self < 0 }
    fn negate(&self) -> i32 { -(*self) }
}

fn cvt<T: IsNegative>(t: T) -> Result<T, i32> {
    if t.is_negative() { Err(t.negate()) } else { Ok(t) }
}

fn main() {
    let r = std::panic::catch_unwind(|| cvt(i32::MIN));
    match r {
        Err(_) => println!("BUG REPRODUCED: cvt(i32::MIN) panics on negate"),
        Ok(_) => println!("no panic"),
    }
}
