// Bug: VxWorks Command::spawn redirects stdio with dup2 and only restores it after rtpSpawn,
//      so an early error (e.g. failing chdir) returns to the caller while parent stdio remains
//      pointed at the file the user tried to attach to the child.
// Expected: spawn() error must not permanently mutate the caller's stdio.
// Observed: this host PoC reproduces the same dup2-then-fail-without-restore pattern using the
//      regular Unix libc, and shows that after a failed setup stdin still points at the redirect.
// Build/run (Darwin/Linux):
//   rustc /Users/j/src/swival-audits/rust-stdlib/pocs/025-early-error-leaves-redirected-stdio.rs \
//     -o /tmp/poc025 && /tmp/poc025
// Cross-build (metadata): rustc --target=x86_64-wrs-vxworks --emit=metadata ... (toolchain-dependent)

use std::ffi::CString;
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};
use std::io::{Read, Write};

extern "C" {
    fn dup(fd: i32) -> i32;
    fn dup2(src: i32, dst: i32) -> i32;
    fn close(fd: i32) -> i32;
    fn chdir(path: *const i8) -> i32;
}

const STDIN_FILENO: i32 = 0;

fn faux_spawn_buggy(child_stdin_fd: i32, missing_dir: &CString) -> Result<(), &'static str> {
    unsafe {
        let _orig_stdin = dup(STDIN_FILENO);
        if _orig_stdin < 0 {
            return Err("dup failed");
        }
        if dup2(child_stdin_fd, STDIN_FILENO) < 0 {
            return Err("dup2 failed");
        }

        if chdir(missing_dir.as_ptr()) != 0 {
            return Err("chdir failed");
        }

        let _ = dup2(_orig_stdin, STDIN_FILENO);
        close(_orig_stdin);
        Ok(())
    }
}

fn main() {
    let tmp_path = "/tmp/poc025-redirect-input.txt";
    {
        let mut f = File::create(tmp_path).unwrap();
        writeln!(f, "REDIRECTED-STDIN-CONTENT").unwrap();
    }
    let stdin_redirect = File::open(tmp_path).unwrap();
    let fd = stdin_redirect.as_raw_fd();

    let saved_stdin = unsafe { dup(STDIN_FILENO) };
    assert!(saved_stdin >= 0);

    let bad_dir = CString::new("/this/definitely/does/not/exist/poc025").unwrap();
    let res = faux_spawn_buggy(fd, &bad_dir);
    assert!(res.is_err(), "faux_spawn must fail at chdir");

    let mut probe_buf = [0u8; 32];
    let stdin_now = unsafe { File::from_raw_fd(libc_dup(STDIN_FILENO)) };
    let mut s = stdin_now;
    let n = s.read(&mut probe_buf).unwrap_or(0);
    let observed = String::from_utf8_lossy(&probe_buf[..n]);

    unsafe {
        dup2(saved_stdin, STDIN_FILENO);
        close(saved_stdin);
    }

    println!("post-failed-spawn stdin reads: {observed:?}");
    if observed.contains("REDIRECTED-STDIN-CONTENT") {
        println!("BUG TRIGGERED: parent stdin remained pointed at redirect after failed spawn");
        std::process::exit(0);
    } else {
        eprintln!("UNEXPECTED: stdin not corrupted (host shell may not allow redirect)");
        std::process::exit(0);
    }
}

fn libc_dup(fd: i32) -> i32 {
    unsafe { dup(fd) }
}
