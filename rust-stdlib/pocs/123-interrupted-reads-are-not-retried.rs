// bug: read_file at library/std_detect/src/detect/os/linux/mod.rs:23 treats every
//      libc::read returning -1 as fatal, including transient EINTR.
// expected: retry on EINTR.
// observed: an EINTR returned by read makes read_file abort with a generic error.
// target: linux/darwin. Reproduces the same match logic on a real pipe interrupted
//         by SIGUSR1 with a no-op handler installed without SA_RESTART.
// build/run: rustc 123-interrupted-reads-are-not-retried.rs -o /tmp/poc123 && /tmp/poc123

use std::os::raw::{c_int, c_void};
use std::ptr;
use std::thread;
use std::time::Duration;

#[repr(C)]
struct sigaction {
    sa_handler: usize,
    sa_mask: [u64; 16],
    sa_flags: c_int,
}

extern "C" {
    fn pipe(fds: *mut c_int) -> c_int;
    fn read(fd: c_int, buf: *mut c_void, count: usize) -> isize;
    fn close(fd: c_int) -> c_int;
    fn sigaction(signum: c_int, act: *const sigaction, oldact: *mut sigaction) -> c_int;
    fn kill(pid: c_int, sig: c_int) -> c_int;
    fn getpid() -> c_int;
    #[cfg(target_os = "macos")]
    fn __error() -> *mut c_int;
    #[cfg(target_os = "linux")]
    fn __errno_location() -> *mut c_int;
}

#[cfg(target_os = "macos")]
unsafe fn errno() -> c_int { *__error() }
#[cfg(target_os = "linux")]
unsafe fn errno() -> c_int { *__errno_location() }

const SIGUSR1: c_int = 30;
const EINTR: c_int = 4;

extern "C" fn handler(_: c_int) {}

fn vulnerable_read_file(fd: c_int) -> Result<(), String> {
    let mut buf = [0u8; 4096];
    loop {
        let n = unsafe { read(fd, buf.as_mut_ptr() as *mut c_void, buf.len()) };
        match n {
            -1 => {
                let e = unsafe { errno() };
                return Err(format!("read failed errno={}", e));
            }
            0 => return Ok(()),
            _ => {}
        }
    }
}

fn main() {
    unsafe {
        let act = sigaction { sa_handler: handler as usize, sa_mask: [0; 16], sa_flags: 0 };
        sigaction(SIGUSR1, &act, ptr::null_mut());

        let mut fds = [0i32; 2];
        assert_eq!(pipe(fds.as_mut_ptr()), 0);
        let pid = getpid();

        thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            kill(pid, SIGUSR1);
        });

        let res = vulnerable_read_file(fds[0]);
        let e = errno();
        close(fds[0]);
        close(fds[1]);

        match res {
            Err(msg) if e == EINTR || msg.contains("errno=4") || msg.contains(&format!("errno={}", EINTR)) => {
                println!("BUG TRIGGERED: read returned EINTR and was treated as fatal: {}", msg);
            }
            Err(msg) => {
                println!("BUG TRIGGERED (different errno): {}", msg);
            }
            Ok(()) => {
                println!("read returned EOF before EINTR could be observed");
            }
        }
    }
}
