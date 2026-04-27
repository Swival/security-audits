// Bug: uefi_fs::File::from_path opens the volume protocol via open_volume_from_device_path,
//      then opens a child file from it but never wraps the volume protocol in `Self`, so
//      Drop never closes the volume handle on success or unwind.
// Expected: the volume protocol must be owned (RAII) so close() runs in all paths.
// Observed: this host model reproduces the lifecycle: only the "child" handle is closed,
//      the volume handle is leaked.
// Build/run (host):
//   rustc /Users/j/src/swival-audits/rust-stdlib/pocs/030-volume-handle-leak-in-from-path.rs \
//     -o /tmp/poc030 && /tmp/poc030
// Cross-build:
//   rustc --target=x86_64-unknown-uefi --emit=metadata --edition=2021 \
//     /Users/j/src/swival-audits/rust-stdlib/pocs/030-volume-handle-leak-in-from-path.rs

use std::cell::RefCell;

thread_local! {
    static OPENED: RefCell<Vec<u32>> = RefCell::new(Vec::new());
    static CLOSED: RefCell<Vec<u32>> = RefCell::new(Vec::new());
    static NEXT: RefCell<u32> = RefCell::new(1);
}

fn open_protocol(label: &str) -> u32 {
    let id = NEXT.with(|c| { let mut c = c.borrow_mut(); let v = *c; *c += 1; v });
    OPENED.with(|o| o.borrow_mut().push(id));
    println!("  open  {label}: handle {id}");
    id
}

struct UefiFile { protocol: u32 }
impl Drop for UefiFile {
    fn drop(&mut self) {
        CLOSED.with(|c| c.borrow_mut().push(self.protocol));
        println!("  close handle {}", self.protocol);
    }
}

fn buggy_from_path() -> UefiFile {
    let vol = open_protocol("volume");
    let child = open_child_from(vol);
    UefiFile { protocol: child }
}

fn open_child_from(_vol: u32) -> u32 {
    open_protocol("child")
}

fn main() {
    {
        let _f = buggy_from_path();
    }
    let opened = OPENED.with(|o| o.borrow().clone());
    let closed = CLOSED.with(|c| c.borrow().clone());
    println!("opened: {opened:?}");
    println!("closed: {closed:?}");
    let leaked: Vec<_> = opened.iter().copied().filter(|h| !closed.contains(h)).collect();
    println!("leaked: {leaked:?}");
    if leaked == vec![1] {
        println!("BUG TRIGGERED: volume protocol handle leaked (only child closed)");
        std::process::exit(0);
    } else {
        eprintln!("UNEXPECTED: leak set differs");
        std::process::exit(1);
    }
}
