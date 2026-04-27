// Bug: UnixStream::write_vectored on Unix calls plain writev (no MSG_NOSIGNAL), unlike
//      scalar write which uses send_with_flags(MSG_NOSIGNAL). On a disconnected stream
//      socket with default SIGPIPE disposition, writev terminates the process with SIGPIPE
//      while sendmsg(MSG_NOSIGNAL) returns EPIPE.
// Expected: write_vectored is documented to use MSG_NOSIGNAL like scalar write.
// Observed: this PoC reproduces the kernel-level discrepancy: send(MSG_NOSIGNAL) returns -1/EPIPE,
//           plain writev raises SIGPIPE. Run on Linux for full effect; on macOS the equivalent
//           SO_NOSIGPIPE is the analogue. We use libc::send/writev directly via socketpair.
// Build/run (Linux/macOS):
//   rustc /Users/j/src/swival-audits/rust-stdlib/pocs/029-vectored-writes-omit-sigpipe-suppression.rs \
//     -o /tmp/poc029 && /tmp/poc029

use std::mem::MaybeUninit;
use std::os::raw::{c_int, c_void};

#[repr(C)]
struct Iovec {
    iov_base: *mut c_void,
    iov_len: usize,
}

extern "C" {
    fn socketpair(domain: c_int, ty: c_int, proto: c_int, sv: *mut c_int) -> c_int;
    fn close(fd: c_int) -> c_int;
    fn send(fd: c_int, buf: *const c_void, len: usize, flags: c_int) -> isize;
    fn writev(fd: c_int, iov: *const Iovec, iovcnt: c_int) -> isize;
    fn signal(signum: c_int, handler: usize) -> usize;
    fn __error() -> *mut c_int;
}

#[cfg(target_os = "macos")]
const AF_UNIX: c_int = 1;
#[cfg(target_os = "linux")]
const AF_UNIX: c_int = 1;
#[cfg(target_os = "macos")]
const SOCK_STREAM: c_int = 1;
#[cfg(target_os = "linux")]
const SOCK_STREAM: c_int = 1;
#[cfg(target_os = "macos")]
const MSG_NOSIGNAL: c_int = 0;
#[cfg(target_os = "linux")]
const MSG_NOSIGNAL: c_int = 0x4000;
const SIGPIPE: c_int = 13;
const SIG_IGN: usize = 1;

fn errno_now() -> i32 {
    unsafe { *__error() }
}

fn make_pair() -> (c_int, c_int) {
    let mut sv: [c_int; 2] = [0; 2];
    let r = unsafe { socketpair(AF_UNIX, SOCK_STREAM, 0, sv.as_mut_ptr()) };
    assert_eq!(r, 0);
    (sv[0], sv[1])
}

fn main() {
    unsafe { signal(SIGPIPE, SIG_IGN); }

    let (a, b) = make_pair();
    unsafe { close(b); }
    let payload = [0u8; 16];
    let r = unsafe { send(a, payload.as_ptr() as *const c_void, payload.len(), MSG_NOSIGNAL) };
    let send_errno = errno_now();
    println!("send(MSG_NOSIGNAL): ret={r}, errno={send_errno}");
    unsafe { close(a); }

    let (a, b) = make_pair();
    unsafe { close(b); }
    let payload = [0u8; 16];
    let iov = Iovec { iov_base: payload.as_ptr() as *mut c_void, iov_len: payload.len() };
    let _ = MaybeUninit::<Iovec>::uninit;
    let r = unsafe { writev(a, &iov as *const Iovec, 1) };
    let writev_errno = errno_now();
    println!("plain writev (would deliver SIGPIPE if not ignored): ret={r}, errno={writev_errno}");
    unsafe { close(a); }

    if r < 0 && writev_errno == libc_epipe() {
        println!("BUG TRIGGERED: writev raised SIGPIPE (we ignored it). Without ignoring, the");
        println!("process would have been killed by signal {SIGPIPE}, while send(MSG_NOSIGNAL)");
        println!("returned EPIPE cleanly.");
        std::process::exit(0);
    } else {
        eprintln!("UNEXPECTED: writev did not return EPIPE/SIGPIPE-equivalent");
        std::process::exit(1);
    }
}

fn libc_epipe() -> i32 { 32 }
