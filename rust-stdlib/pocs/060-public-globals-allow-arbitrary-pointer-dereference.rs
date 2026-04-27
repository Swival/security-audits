// Bug: std::os::uefi::env::globals exposes mutable atomic pointers; safe code can
//      store an arbitrary pointer in SYSTEM_TABLE then call env::boot_services(),
//      which dereferences it inside std unsafe code.
// Expected: globals are not reachable from external safe code.
// Observed: pre-patch, `pub mod globals` is reachable; this PoC simulates the same
//      reachability pattern by exposing a public mutable atomic pointer that is later
//      dereferenced by a "safe" wrapper. On a UEFI std build, the real path is
//      `env::globals::SYSTEM_TABLE.store(...); env::boot_services();`.
// Build/run: rustc 060-public-globals-allow-arbitrary-pointer-dereference.rs -o /tmp/poc060 && /tmp/poc060
// Target note: the actual vulnerable path is target_os="uefi"; this file demonstrates
//      the reachability pattern on the host so it can be compiled and run.

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

mod globals {
    use super::*;
    pub static SYSTEM_TABLE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
    pub static BOOT_SERVICES_FLAG: AtomicBool = AtomicBool::new(false);
}

#[repr(C)]
struct FakeSystemTable {
    boot_services: *mut c_void,
}

fn boot_services() -> Option<*mut c_void> {
    if !globals::BOOT_SERVICES_FLAG.load(Ordering::Acquire) {
        return None;
    }
    let p = globals::SYSTEM_TABLE.load(Ordering::Acquire) as *const FakeSystemTable;
    Some(unsafe { (*p).boot_services })
}

fn main() {
    let mut sentinel = FakeSystemTable { boot_services: 0xdeadbeef as *mut c_void };
    globals::BOOT_SERVICES_FLAG.store(true, Ordering::Release);
    globals::SYSTEM_TABLE.store(&mut sentinel as *mut _ as *mut c_void, Ordering::Release);

    let bs = boot_services().expect("flag set");
    println!("safe-call dereferenced attacker pointer; got boot_services = {:p}", bs);
    assert_eq!(bs as usize, 0xdeadbeef);
}
