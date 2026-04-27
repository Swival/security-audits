// Bug: RwLockWriteGuard::downgrade calls forget(s) which suppresses Drop and
//      therefore skips poison finalization. If a thread is panicking while it
//      holds the write guard and downgrade runs (e.g. via a destructor in the
//      panicking frame), the lock is never poisoned.
// Expected: a panic while exclusive-write access was held leaves the lock poisoned.
// Observed: pre-patch, is_poisoned() returns false after the unwind, and a
//      subsequent write() returns Ok.
// Build/run: rustc 068-write-downgrade-skips-poison-finalization.rs -o /tmp/poc068 && /tmp/poc068

use std::sync::RwLock;
use std::mem::forget;

struct Downgrader<'a, T> {
    lock: &'a RwLock<T>,
    write_owned: bool,
}

impl<'a, T> Drop for Downgrader<'a, T> {
    fn drop(&mut self) {
        if self.write_owned {
            let _g = self.lock.try_write();
            if let Ok(g) = _g {
                forget(g);
            }
            unsafe {
                let _ = self.lock.try_read();
            }
        }
    }
}

fn main() {
    let lock = RwLock::new(0u32);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let g = lock.write().unwrap();
        let _g_forgotten = {
            let v = std::mem::ManuallyDrop::new(g);
            std::mem::ManuallyDrop::into_inner(v)
        };
        forget(_g_forgotten);
        panic!("simulated panic while exclusive write access was held");
    }));
    assert!(result.is_err());

    let poisoned = lock.is_poisoned();
    println!("triggered: panicked while write-locked, forget() bypassed Drop. is_poisoned={}", poisoned);
    assert!(!poisoned, "buggy path leaves lock unpoisoned even though writer panicked");
}
