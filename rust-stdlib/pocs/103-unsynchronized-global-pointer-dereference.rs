// Bug: SGX env store publishes/loads ENV pointer with Ordering::Relaxed,
//      so reader can observe non-null pointer before initialization writes are
//      visible.
// Target: x86_64-fortanix-unknown-sgx (env path is target_env = "sgx")
// Expected: Release on store, Acquire on load to publish initialization.
// Observed: Relaxed/Relaxed lacks happens-before for boxed Mutex contents.
// Build (host stress check, simulates the load/store pattern):
//   rustc 103-unsynchronized-global-pointer-dereference.rs -O \
//     -o /tmp/poc103 && /tmp/poc103
// Cross-compile check (compile-only):
//   rustc --target=x86_64-fortanix-unknown-sgx --emit=metadata \
//     --crate-type=lib 103-unsynchronized-global-pointer-dereference.rs
//
// The host harness models the relaxed-load reader: it spins polling a Relaxed
// pointer and dereferences a heap struct whose body was written non-atomically
// before the relaxed publication. On weak-memory hardware this can observe the
// non-null pointer before the body initialization, which is the bug. On x86
// the visibility ordering is empirically TSO so the corruption is rare, but
// the data race is reportable under loom/Miri (-Zmiri-disable-isolation).

use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::Once;
use std::thread;

#[repr(C)]
struct Inner {
    a: u64,
    b: u64,
    c: u64,
    d: u64,
}

static ENV: AtomicPtr<Inner> = AtomicPtr::new(std::ptr::null_mut());
static INIT: Once = Once::new();

fn create_buggy() -> &'static Inner {
    INIT.call_once(|| {
        let p = Box::into_raw(Box::new(Inner { a: 1, b: 2, c: 3, d: 4 }));
        ENV.store(p, Ordering::Relaxed);
    });
    unsafe { &*ENV.load(Ordering::Relaxed) }
}

fn read_buggy() -> Option<&'static Inner> {
    unsafe { (ENV.load(Ordering::Relaxed) as *const Inner).as_ref() }
}

fn main() {
    let h = thread::spawn(|| {
        for _ in 0..100_000 {
            if let Some(r) = read_buggy() {
                let _ = (r.a, r.b, r.c, r.d);
                break;
            }
        }
    });
    let _ = create_buggy();
    h.join().unwrap();
    println!("relaxed publish/load pattern executed; data race per Rust memory model");
}
