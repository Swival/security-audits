// Bug: SGX __rust_c_dealloc constructs a Layout with from_size_align_unchecked from
//      external C ABI inputs and forwards to dealloc, violating Layout invariants
//      when callers pass align=0 or non-power-of-two align.
// Expected: invalid layout silently ignored.
// Observed: pre-patch, from_size_align_unchecked with align=0 violates the
//      precondition; with debug assertions on, it aborts.
// Build/run: rustc -Cdebug-assertions=on 070-unchecked-c-deallocation-layout.rs -o /tmp/poc070 && /tmp/poc070

use std::alloc::Layout;

fn buggy_c_dealloc_layout(size: usize, align: usize) -> Layout {
    unsafe { Layout::from_size_align_unchecked(size, align) }
}

fn main() {
    let r = std::panic::catch_unwind(|| {
        let _l = buggy_c_dealloc_layout(16, 0);
    });
    if r.is_err() {
        println!("triggered: from_size_align_unchecked aborted on align=0");
    } else {
        let bad = buggy_c_dealloc_layout(16, 0);
        println!("triggered: from_size_align_unchecked produced invalid Layout: align={} size={}",
            bad.align(), bad.size());
    }
}
