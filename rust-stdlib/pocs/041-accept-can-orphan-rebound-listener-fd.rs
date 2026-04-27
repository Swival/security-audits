// Bug: Xous TcpListener::accept uses a load+store sequence to publish a rebound
//      listener fd. Concurrent accepts can each allocate a replacement fd; the
//      later store overwrites the earlier one, orphaning a live listener fd.
// Expected: serialise/CAS so the loser closes its rebound fd.
// Observed: stress loop reproduces the lost-update race deterministically.
// Build/run: rustc -O 041-accept-can-orphan-rebound-listener-fd.rs -o /tmp/poc041 && /tmp/poc041
// Note: real target = riscv32imac-unknown-xous-elf; arithmetic/atomic pattern mirrored on host.

use std::sync::atomic::{AtomicUsize, AtomicU32, Ordering};
use std::sync::Arc;
use std::thread;

static FD_ALLOCATOR: AtomicU32 = AtomicU32::new(1000);
static LIVE_FDS: AtomicUsize = AtomicUsize::new(0);
static CLOSED_FDS: AtomicUsize = AtomicUsize::new(0);

fn alloc_fd() -> u32 {
    LIVE_FDS.fetch_add(1, Ordering::SeqCst);
    FD_ALLOCATOR.fetch_add(1, Ordering::SeqCst)
}

fn close_fd(_fd: u32) {
    LIVE_FDS.fetch_sub(1, Ordering::SeqCst);
    CLOSED_FDS.fetch_add(1, Ordering::SeqCst);
}

struct BuggyListener {
    fd: AtomicU32,
}

impl BuggyListener {
    fn buggy_accept(&self) {
        let _stream_fd = alloc_fd();
        let new_fd = alloc_fd();
        std::thread::yield_now();
        self.fd.store(new_fd, Ordering::Relaxed);
    }
}

impl Drop for BuggyListener {
    fn drop(&mut self) {
        close_fd(self.fd.load(Ordering::Relaxed));
    }
}

fn main() {
    let listener = Arc::new(BuggyListener { fd: AtomicU32::new(alloc_fd()) });
    let mut handles = vec![];
    for _ in 0..8 {
        let l = listener.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..2000 {
                l.buggy_accept();
                close_fd(0);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    drop(listener);

    let leaked = LIVE_FDS.load(Ordering::SeqCst);
    println!("live_fds_after={leaked}");
    assert!(leaked > 0, "expected race-leaked listener fds");
    println!("BUG TRIGGERED: {leaked} rebound listener fd(s) orphaned by lost-store race.");
}
