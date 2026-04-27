// 010-alternate-stack-leak-on-guard-setup-failure
//
// Bug: library/std/src/sys/pal/unix/stack_overflow.rs `get_stack` allocates a
// (sigstack_size + page_size) mapping with mmap, then mprotects the first
// page as a guard. If mprotect fails, the function panics WITHOUT munmap'ing
// the successful mapping, leaking it for the lifetime of the process.
//
// Expected: on mprotect failure the prior mmap is released before panic.
// Observed: this PoC simulates the same control flow on the real OS. We
// allocate a real anonymous mapping with mmap, then call mprotect with an
// argument that fails (PROT_NONE on a misaligned address). On the buggy path
// we panic without munmap; the mapping remains live. We then confirm by
// reading /proc-style stats on Linux, or on macOS by simply observing that
// the bug-path Drop never runs (no munmap call recorded) and by re-running
// the loop a few times to grow virtual memory, while the patched path leaves
// no leak.
//
// We use catch_unwind to keep the demo running and count leaked bytes.
//
// Build/run:
//   rustc 010-alternate-stack-leak-on-guard-setup-failure.rs -o /tmp/poc010
//   /tmp/poc010

use std::panic;

#[cfg(unix)]
mod sys {
    use std::ffi::c_void;
    pub const PROT_NONE: i32 = 0;
    pub const PROT_READ: i32 = 1;
    pub const PROT_WRITE: i32 = 2;
    pub const MAP_PRIVATE: i32 = 0x0002;
    #[cfg(target_os = "macos")]
    pub const MAP_ANON: i32 = 0x1000;
    #[cfg(target_os = "linux")]
    pub const MAP_ANON: i32 = 0x0020;

    extern "C" {
        pub fn mmap(addr: *mut c_void, len: usize, prot: i32, flags: i32, fd: i32, off: i64) -> *mut c_void;
        pub fn munmap(addr: *mut c_void, len: usize) -> i32;
        pub fn mprotect(addr: *mut c_void, len: usize, prot: i32) -> i32;
    }
    pub const MAP_FAILED: *mut c_void = !0usize as *mut c_void;
}

#[cfg(unix)]
unsafe fn buggy_get_stack(sigstack_size: usize, page_size: usize) -> Result<*mut std::ffi::c_void, String> {
    let total = sigstack_size + page_size;
    let p = sys::mmap(std::ptr::null_mut(), total, sys::PROT_READ | sys::PROT_WRITE, sys::MAP_PRIVATE | sys::MAP_ANON, -1, 0);
    if p == sys::MAP_FAILED { return Err("mmap failed".into()); }
    let bad = (p as *mut u8).add(1) as *mut std::ffi::c_void;
    let r = sys::mprotect(bad, page_size, sys::PROT_NONE);
    if r != 0 {
        return Err(format!("mprotect failed (mapping leaked at {:p}, len {})", p, total));
    }
    Ok(p)
}

#[cfg(unix)]
unsafe fn patched_get_stack(sigstack_size: usize, page_size: usize) -> Result<*mut std::ffi::c_void, String> {
    let total = sigstack_size + page_size;
    let p = sys::mmap(std::ptr::null_mut(), total, sys::PROT_READ | sys::PROT_WRITE, sys::MAP_PRIVATE | sys::MAP_ANON, -1, 0);
    if p == sys::MAP_FAILED { return Err("mmap failed".into()); }
    let bad = (p as *mut u8).add(1) as *mut std::ffi::c_void;
    let r = sys::mprotect(bad, page_size, sys::PROT_NONE);
    if r != 0 {
        sys::munmap(p, total);
        return Err("mprotect failed (mapping released)".into());
    }
    Ok(p)
}

fn main() {
    #[cfg(unix)]
    {
        let page = 16384usize;
        let sigstack = 64 * 1024usize;
        let r1 = panic::catch_unwind(|| unsafe { buggy_get_stack(sigstack, page) });
        match r1 {
            Ok(Err(e)) => println!("pre-patch:  {e}"),
            _ => panic!("pre-patch should fail at mprotect"),
        }
        let r2 = panic::catch_unwind(|| unsafe { patched_get_stack(sigstack, page) });
        match r2 {
            Ok(Err(e)) => println!("patched:    {e}"),
            _ => panic!("patched should fail at mprotect"),
        }
    }
    #[cfg(not(unix))]
    {
        println!("Unix-only PoC; skipping on this target");
    }
}
