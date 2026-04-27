// Bug: SGX __rust_c_alloc constructs a Layout with from_size_align_unchecked from
//      external C ABI inputs. Invalid alignment (zero, non-power-of-two) violates
//      Layout invariants.
// Expected: invalid layout returns null without constructing an invalid Layout.
// Observed: pre-patch, calling from_size_align_unchecked with align=3 hits
//      `Layout::from_size_align_unchecked requires that align is a power of 2`
//      under -Cdebug-assertions=on.
// Build/run: rustc -Cdebug-assertions=on 069-unchecked-c-allocation-layout.rs -o /tmp/poc069 && /tmp/poc069
// Target note: on real SGX targets the symbol is exported; this PoC reproduces the
//      precondition check inside the standard library.

use std::alloc::Layout;

fn buggy_c_alloc(size: usize, align: usize) -> Layout {
    unsafe { Layout::from_size_align_unchecked(size, align) }
}

fn main() {
    let r = std::panic::catch_unwind(|| {
        let _l = buggy_c_alloc(8, 3);
    });
    if r.is_err() {
        println!("triggered: from_size_align_unchecked aborted on align=3");
    } else {
        let bad = buggy_c_alloc(8, 3);
        println!("triggered: from_size_align_unchecked produced invalid Layout: align={} size={}",
            bad.align(), bad.size());
    }
}
