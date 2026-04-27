// Bug: uefi_fs::mkdir opens the target path to test existence; on Ok(_) it discards the
//      raw NonNull<file::Protocol> without wrapping in `File`, so Drop never closes the
//      firmware handle. Each mkdir-on-existing-path leaks one handle.
// Expected: wrap the protocol in File (RAII) so Drop closes it before returning AlreadyExists.
// Observed: this host model reproduces the leak: open without owner -> close never invoked.
// Build/run (host):
//   rustc /Users/j/src/swival-audits/rust-stdlib/pocs/031-existence-check-leaks-opened-handle.rs \
//     -o /tmp/poc031 && /tmp/poc031
// Cross-build:
//   rustc --target=x86_64-unknown-uefi --emit=metadata --edition=2021 \
//     /Users/j/src/swival-audits/rust-stdlib/pocs/031-existence-check-leaks-opened-handle.rs

use std::cell::RefCell;

thread_local! {
    static OPEN_COUNT: RefCell<u32> = RefCell::new(0);
    static CLOSE_COUNT: RefCell<u32> = RefCell::new(0);
}

fn open_protocol() -> u32 {
    OPEN_COUNT.with(|c| { *c.borrow_mut() += 1; *c.borrow() })
}

struct UefiFile { protocol: u32 }
impl Drop for UefiFile {
    fn drop(&mut self) {
        CLOSE_COUNT.with(|c| *c.borrow_mut() += 1);
        let _ = self.protocol;
    }
}

fn buggy_mkdir_path_exists() -> Result<(), &'static str> {
    let _ = open_protocol();
    Err("AlreadyExists")
}

fn main() {
    for _ in 0..10 {
        let _ = buggy_mkdir_path_exists();
    }
    let opens = OPEN_COUNT.with(|c| *c.borrow());
    let closes = CLOSE_COUNT.with(|c| *c.borrow());
    println!("opens={opens} closes={closes}");
    if opens == 10 && closes == 0 {
        println!("BUG TRIGGERED: existence-check handle leaked every iteration");
        std::process::exit(0);
    } else {
        eprintln!("UNEXPECTED: closes recorded");
        std::process::exit(1);
    }
}
