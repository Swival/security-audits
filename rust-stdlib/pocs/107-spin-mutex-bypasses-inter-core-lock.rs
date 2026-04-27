// Bug: ITRON SpinMutex::with_locked skips the atomic spinlock when dispatching
//      is already disabled, exposing &mut T while another core can also enter.
// Target: ITRON / SOLID (target_os = "solid_asp3"). Toolchain unavailable on host.
// Expected: always swap(true) on locked atomic; only dispatch ena/dis is conditional.
// Observed: when sns_dsp() != 0 nothing is acquired and &mut T is yielded.
//
// Build (compile-only host model demonstrating the buggy control flow):
//   rustc 107-spin-mutex-bypasses-inter-core-lock.rs -o /tmp/poc107 && /tmp/poc107

use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicBool, Ordering};

static FAKE_DSP_DISABLED: AtomicBool = AtomicBool::new(true);

unsafe fn sns_dsp() -> i32 {
    if FAKE_DSP_DISABLED.load(Ordering::Relaxed) { 1 } else { 0 }
}

struct SpinMutex<T> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Sync for SpinMutex<T> {}

impl<T> SpinMutex<T> {
    pub const fn new(x: T) -> Self {
        Self { locked: AtomicBool::new(false), data: UnsafeCell::new(x) }
    }
    pub fn with_locked_buggy<R>(&self, f: impl FnOnce(&mut T) -> R) -> (R, bool) {
        let mut took_lock = false;
        if unsafe { sns_dsp() } == 0 {
            while self.locked.swap(true, Ordering::Acquire) {}
            took_lock = true;
        }
        let r = f(unsafe { &mut *self.data.get() });
        if took_lock {
            self.locked.store(false, Ordering::Release);
        }
        (r, took_lock)
    }
}

fn main() {
    let m = SpinMutex::new(0u32);
    FAKE_DSP_DISABLED.store(true, Ordering::Relaxed);
    let (_v, took) = m.with_locked_buggy(|x| { *x = 42; *x });
    let raw_locked = m.locked.load(Ordering::Relaxed);
    println!("dsp_disabled_on_entry=true, took_inter_core_lock={took}, locked_atomic_observed={raw_locked}");
    assert_eq!(took, false, "BUG REPRODUCED: entered &mut T without inter-core lock");
    assert_eq!(raw_locked, false, "atomic was never set; another core can also enter");
    println!("BUG REPRODUCED");
}
