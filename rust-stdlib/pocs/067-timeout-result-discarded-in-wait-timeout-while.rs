// Bug: Condvar::wait_timeout_while in nonpoison discards the WaitTimeoutResult and
//      checks the predicate again. If the timeout elapsed but another thread has set
//      the predicate to false in the meantime, the function returns
//      WaitTimeoutResult(false), misreporting timeout as predicate satisfaction.
// Expected: when wait_timeout reports timed_out, the function returns timed_out=true.
// Observed: pre-patch, timed_out=false even though the deadline has elapsed.
// Build/run: rustc 067-timeout-result-discarded-in-wait-timeout-while.rs -o /tmp/poc067 && /tmp/poc067

use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy)]
struct WaitTimeoutResult(bool);
impl WaitTimeoutResult { fn timed_out(self) -> bool { self.0 } }

fn buggy_wait_timeout_while<F>(
    cv: &Condvar,
    m: &Mutex<bool>,
    dur: Duration,
    mut condition: F,
) -> WaitTimeoutResult
where
    F: FnMut(&mut bool) -> bool,
{
    let mut guard = m.lock().unwrap();
    let start = Instant::now();
    while condition(&mut *guard) {
        let timeout = match dur.checked_sub(start.elapsed()) {
            Some(t) => t,
            None => return WaitTimeoutResult(true),
        };
        let (g, _wtr) = cv.wait_timeout(guard, timeout).unwrap();
        guard = g;
    }
    WaitTimeoutResult(false)
}

fn main() {
    let pair = Arc::new((Mutex::new(false), Condvar::new()));
    let pair2 = pair.clone();

    let waiter = thread::spawn(move || {
        let (m, cv) = &*pair2;
        let start = Instant::now();
        let r = buggy_wait_timeout_while(cv, m, Duration::from_millis(20), |done| !*done);
        (r, start.elapsed())
    });

    thread::sleep(Duration::from_millis(5));
    {
        let (m, cv) = &*pair;
        let mut g = m.lock().unwrap();
        thread::sleep(Duration::from_millis(80));
        *g = true;
        drop(g);
        cv.notify_all();
    }

    let (r, elapsed) = waiter.join().unwrap();
    assert!(elapsed >= Duration::from_millis(50), "timeout must have elapsed");
    assert!(!r.timed_out(), "buggy result reports timed_out=false despite real timeout");
    println!("triggered: elapsed={:?} timed_out={}", elapsed, r.timed_out());
}
