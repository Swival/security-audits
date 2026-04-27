// bug: read_file in library/std_detect/src/detect/os/linux/mod.rs opens a file with
//      libc::open and only closes it via explicit libc::close calls. If Vec::reserve
//      panics after open succeeds, the descriptor is leaked.
// expected: descriptor cleaned up on every exit path including unwinding.
// observed: when the alloc-step panics under catch_unwind, the fd remains open.
// target: linux. On darwin we mirror the exact pattern with libc::open/close on
//         /dev/null and observe the same fd leak.
// build/run: rustc 122-file-descriptor-leak-on-allocation-panic.rs -o /tmp/poc122 && /tmp/poc122

use std::panic;

extern "C" {
    fn open(path: *const u8, flags: i32, ...) -> i32;
    fn close(fd: i32) -> i32;
    fn fcntl(fd: i32, cmd: i32) -> i32;
}

const O_RDONLY: i32 = 0;
const F_GETFD: i32 = 1;

fn fd_is_open(fd: i32) -> bool {
    unsafe { fcntl(fd, F_GETFD) != -1 }
}

fn vulnerable_read_file_simulated(reserve_panics: bool) -> Result<(), String> {
    let path = b"/dev/null\0";
    unsafe {
        let file = open(path.as_ptr(), O_RDONLY);
        if file == -1 {
            return Err("open failed".into());
        }

        if reserve_panics {
            panic!("simulated Vec::reserve allocation panic");
        }

        close(file);
        Ok(())
    }
}

fn main() {
    let result = panic::catch_unwind(|| vulnerable_read_file_simulated(true));
    assert!(result.is_err(), "panic not propagated");

    let mut leaked_count = 0;
    for fd in 3..256 {
        if fd_is_open(fd) {
            leaked_count += 1;
        }
    }

    let result2 = panic::catch_unwind(|| vulnerable_read_file_simulated(true));
    let _ = result2;
    let result3 = panic::catch_unwind(|| vulnerable_read_file_simulated(true));
    let _ = result3;

    let mut after_count = 0;
    for fd in 3..256 {
        if fd_is_open(fd) {
            after_count += 1;
        }
    }

    assert!(after_count > leaked_count, "no leak detected");
    println!("BUG TRIGGERED: {} leaked fds before, {} after two more panics", leaked_count, after_count);
}
