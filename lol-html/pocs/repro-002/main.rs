// Reproducer for finding 002: TypedChildCounterMap bypasses the memory limiter.
//
// Registers an :nth-of-type selector to enable typed child counters.
// Streams many distinct custom element names. If the bug is present, RSS
// grows without bound while max_allowed_memory_usage is set very small.

use lol_html::html_content::Element;
use lol_html::{HtmlRewriter, MemorySettings, Settings, element};
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
        .unwrap_or(1_000_000);

    // Use a :nth-of-type selector to force typed counters to be enabled.
    let handlers = vec![element!("*:nth-of-type(2)", |_el: &mut Element<'_, '_>| {
        Ok(())
    })];

    let settings = Settings {
        element_content_handlers: handlers,
        memory_settings: MemorySettings {
            max_allowed_memory_usage: 100_000, // 100 KB
            ..MemorySettings::default()
        },
        ..Settings::new()
    };
    // Sink everything to /dev/null so we measure only the parser's growth.
    let mut rw = HtmlRewriter::new(settings, |_c: &[u8]| {});

    // open a wrapping div so subsequent siblings count under one parent
    rw.write(b"<html><body><div>").unwrap();

    let start_rss = rss_bytes();
    let mut printed = 0usize;
    for i in 0..n {
        // Use distinct custom element names: <x12345>...</x12345>
        let s = format!("<x{i}></x{i}>");
        if let Err(e) = rw.write(s.as_bytes()) {
            println!("write error after {i} unique tags: {e}");
            return;
        }
        if i - printed >= 50_000 {
            printed = i;
            let cur = rss_bytes();
            println!(
                "after {:>8} unique tags: rss = {:>10} bytes (delta {})",
                i,
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
