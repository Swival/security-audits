// Bug: Hermit IsNegative::negate uses -(*self) on signed-min values, panicking
//      under overflow checks (i8/i16/i32/i64/isize MIN).
// Target: x86_64-unknown-hermit (host panic mirrors the overflow path).
// Expected: checked_neg fallback, mapping to i32::MAX for unrepresentable values.
// Observed: negation panics with "attempt to negate with overflow".
// Build/run: rustc -C overflow-checks=on 105-signed-minimum-negation-overflows.rs \
//            -o /tmp/poc105 && /tmp/poc105

trait IsNegative {
    fn is_negative(&self) -> bool;
    fn negate(&self) -> i32;
}

macro_rules! impl_is_negative {
    ($($t:ident)*) => ($(impl IsNegative for $t {
        fn is_negative(&self) -> bool { *self < 0 }
        fn negate(&self) -> i32 { i32::try_from(-(*self)).unwrap() }
    })*)
}
impl_is_negative! { i8 i16 i64 isize }

fn cvt<T: IsNegative>(t: T) -> Result<T, i32> {
    if t.is_negative() { Err(t.negate()) } else { Ok(t) }
}

fn main() {
    let r = std::panic::catch_unwind(|| cvt(i64::MIN));
    match r {
        Err(_) => println!("BUG REPRODUCED: i64::MIN through Hermit cvt panics on negate"),
        Ok(v) => println!("no panic; value = {:?}", v.map(|_| ())),
    }
}
