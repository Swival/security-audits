// Bug: UserRef<[T]>::iter on SGX builds a Rust &[T] over user-controlled memory by
//      casting self.as_raw_ptr() to &*ptr and calling .iter(). UserRef contractually
//      allows userspace to mutate that memory at any time, so &[T] / &T references
//      violate Rust aliasing.
// Expected: iteration yields &UserRef<T> through raw pointer arithmetic only,
//      never constructing &[T] or &T over user memory.
// Observed: pre-patch, slice::Iter is created over user memory and yields &T.
// Build/run: rustc 071-shared-slice-reference-over-mutable-userspace.rs -o /tmp/poc071 && /tmp/poc071
// Target note: real bug is target_env="sgx"; this PoC reproduces the construction
//      pattern: building slice::Iter over a "userspace" buffer that another
//      observer mutates concurrently demonstrates the aliasing model violation.

use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

static GO: AtomicBool = AtomicBool::new(false);

fn buggy_iter_over_user_mem(ptr: *const u8, len: usize) -> &'static [u8] {
    unsafe { std::slice::from_raw_parts(ptr, len) }
}

fn main() {
    let buf = Box::leak(vec![0u8; 8].into_boxed_slice());
    let slice_ref = buggy_iter_over_user_mem(buf.as_ptr(), buf.len());

    let raw = buf.as_mut_ptr() as usize;
    let h = thread::spawn(move || {
        while !GO.load(Ordering::SeqCst) {}
        for i in 0..1000 {
            unsafe { (raw as *mut u8).write_volatile((i & 0xFF) as u8) };
        }
    });

    GO.store(true, Ordering::SeqCst);
    let mut sum = 0u32;
    for &b in slice_ref.iter() {
        sum = sum.wrapping_add(b as u32);
    }
    h.join().unwrap();

    println!("triggered: built &[u8] over concurrently-mutated user memory; sum={}", sum);
}
