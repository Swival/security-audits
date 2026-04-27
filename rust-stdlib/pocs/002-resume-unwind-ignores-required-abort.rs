// 002-resume-unwind-ignores-required-abort
//
// Bug: std::panic::resume_unwind ignores Some(MustAbort::PanicInHook) returned
// by panic_count::increase(false). Calling resume_unwind from inside a panic
// hook is supposed to abort the process; instead the resumed panic unwinds and
// can be caught.
//
// Expected: process aborts when the second panic is resumed from inside the
// panic hook.
// Observed: catch_unwind successfully captures the resumed payload "second"
// and the program continues normally, printing
//     caught: Some("second")
//
// Build/run:
//   rustc 002-resume-unwind-ignores-required-abort.rs -o /tmp/poc002
//   /tmp/poc002

use std::panic::{self, catch_unwind, resume_unwind};

fn main() {
    panic::set_hook(Box::new(|_| {
        resume_unwind(Box::new("second"));
    }));
    let err = catch_unwind(|| panic!("first")).unwrap_err();
    println!("caught: {:?}", err.downcast_ref::<&str>());
}
