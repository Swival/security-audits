// Reproducer for finding 001: unbounded namespace stack growth on nested foreign tags.
//
// Streams a large number of `<svg>` start tags (without closing tags) and watches
// peak RSS. If the namespace stack is bounded, memory should stabilize. If
// unbounded, memory should grow ~linearly with the number of `<svg>` tags.

use lol_html::{HtmlRewriter, MemorySettings, Settings};
use std::os::raw::c_int;

#[repr(C)]
#[derive(Default)]
struct Rusage {
    ru_utime: [u64; 2],
    ru_stime: [u64; 2],
    ru_maxrss: i64,
    _pad: [i64; 14],
}

unsafe extern "C" {
    fn getrusage(who: c_int, usage: *mut Rusage) -> c_int;
}

fn rss_bytes() -> usize {
    unsafe {
        let mut u: Rusage = Rusage::default();
        getrusage(0, &mut u);
        u.ru_maxrss as usize
    }
}

fn main() {
    let n: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(2_000_000);

    let mut output = vec![];
    let settings = Settings {
        memory_settings: MemorySettings {
            max_allowed_memory_usage: 1, // intentionally tiny
            ..MemorySettings::default()
        },
        ..Settings::new()
    };
    let mut rw = HtmlRewriter::new(settings, |c: &[u8]| output.extend_from_slice(c));

    let chunk = b"<svg>".repeat(1024);

    let start_rss = rss_bytes();
    let mut last_print = 0usize;
    for i in 0..(n / 1024) {
        match rw.write(&chunk) {
            Ok(()) => {}
            Err(e) => {
                println!("write error after {} tags: {e}", i * 1024);
                return;
            }
        }
        if i - last_print >= 256 {
            last_print = i;
            let cur = rss_bytes();
            println!(
                "after {:>8} svg tags: rss = {:>10} bytes (delta {})",
                i * 1024,
                cur,
                cur as isize - start_rss as isize
            );
        }
    }

    let end_rss = rss_bytes();
    println!(
        "final: start_rss={} end_rss={} delta={}",
        start_rss,
        end_rss,
        end_rss as isize - start_rss as isize
    );
}
