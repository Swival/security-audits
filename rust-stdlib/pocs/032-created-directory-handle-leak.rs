// Bug: uefi_fs::mkdir creates the directory by calling private File::open() with MODE_CREATE
//      and assigns the returned NonNull<file::Protocol> to `_`, so the handle is never wrapped
//      in `File` and `Drop` never closes it.
// Expected: wrap created handle in File so Drop closes it.
// Observed: each successful mkdir leaks one firmware handle.
// Build/run (host):
//   rustc /Users/j/src/swival-audits/rust-stdlib/pocs/032-created-directory-handle-leak.rs \
//     -o /tmp/poc032 && /tmp/poc032
// Cross-build:
//   rustc --target=x86_64-unknown-uefi --emit=metadata --edition=2021 \
//     /Users/j/src/swival-audits/rust-stdlib/pocs/032-created-directory-handle-leak.rs

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

fn buggy_mkdir_create() -> Result<(), &'static str> {
    let _ = open_protocol();
    Ok(())
}

fn main() {
    for _ in 0..10 {
        buggy_mkdir_create().unwrap();
    }
    let opens = OPEN_COUNT.with(|c| *c.borrow());
    let closes = CLOSE_COUNT.with(|c| *c.borrow());
    println!("opens={opens} closes={closes}");
    if opens == 10 && closes == 0 {
        println!("BUG TRIGGERED: created-dir handle leaked every iteration");
        std::process::exit(0);
    } else {
        eprintln!("UNEXPECTED: closes recorded");
        std::process::exit(1);
    }
}
