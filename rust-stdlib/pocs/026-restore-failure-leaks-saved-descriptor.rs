// Bug: VxWorks Command::spawn saves original stdio descriptors with libc::dup, then on the
//      restore path uses `t!(cvt_r(|| dup2(orig, std)))` which returns immediately on dup2
//      failure -- before the matching close(orig). This leaks the saved descriptor.
// Expected: every restore failure must close the saved descriptor before returning.
// Observed: this host PoC reproduces the buggy macro and shows that on a forced dup2 failure
//      the saved descriptor stays open (visible by examining /proc-style fd usage or by
//      the dup count growing across iterations).
// Build/run (Darwin/Linux):
//   rustc /Users/j/src/swival-audits/rust-stdlib/pocs/026-restore-failure-leaks-saved-descriptor.rs \
//     -o /tmp/poc026 && /tmp/poc026
// Cross-build: rustc --target=x86_64-wrs-vxworks --emit=metadata ... (toolchain-dependent)

extern "C" {
    fn dup(fd: i32) -> i32;
    fn dup2(src: i32, dst: i32) -> i32;
    fn close(fd: i32) -> i32;
}

fn buggy_restore_round(simulate_dup2_fail: bool) -> Option<i32> {
    unsafe {
        let saved = dup(0);
        if saved < 0 { return None; }
        let dup2_result = if simulate_dup2_fail { -1 } else { dup2(saved, 0) };
        if dup2_result < 0 {
            return Some(saved);
        }
        close(saved);
        None
    }
}

fn main() {
    let mut leaks = Vec::new();
    for _ in 0..16 {
        if let Some(fd) = buggy_restore_round(true) {
            leaks.push(fd);
        }
    }
    println!("leaked saved descriptors: {leaks:?}");
    if leaks.len() == 16 && leaks.iter().all(|&fd| fd > 2) {
        println!("BUG TRIGGERED: every iteration leaks the saved descriptor");
        for &fd in &leaks {
            unsafe { close(fd); }
        }
        std::process::exit(0);
    } else {
        eprintln!("UNEXPECTED: not all iterations leaked");
        std::process::exit(1);
    }
}
