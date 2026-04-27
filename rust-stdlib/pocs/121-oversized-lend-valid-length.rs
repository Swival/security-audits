// bug: PanicWriter::write copies at most 4096 bytes into request buffer, but lends
//      with a valid-length of s.len() (the original input length), advertising more
//      valid bytes than were actually written.
// expected: lent valid length must be min(s.len(), request.0.len()).
// observed: when s.len() > 4096, lent length exceeds initialized payload.
// target: x86_64-unknown-xous-elf (Xous-only). This is a host-side simulation that
//         reproduces the same arithmetic mismatch found at
//         library/std/src/sys/stdio/xous.rs:99 without invoking try_lend.
// build/run: rustc 121-oversized-lend-valid-length.rs -o /tmp/poc121 && /tmp/poc121

fn vulnerable_lend_len(s: &[u8], request: &mut [u8; 4096]) -> usize {
    for (&b, d) in s.iter().zip(request.iter_mut()) {
        *d = b;
    }
    s.len()
}

fn fixed_lend_len(s: &[u8], request: &mut [u8; 4096]) -> usize {
    for (&b, d) in s.iter().zip(request.iter_mut()) {
        *d = b;
    }
    s.len().min(request.len())
}

fn main() {
    let s = vec![b'A'; 8192];
    let mut request = [0u8; 4096];

    let advertised = vulnerable_lend_len(&s, &mut request);
    let actually_initialized = request.len();

    assert_eq!(advertised, 8192);
    assert_eq!(actually_initialized, 4096);
    assert!(advertised > actually_initialized, "bug not triggered");
    println!(
        "BUG TRIGGERED: lend valid length = {} but only {} bytes initialized",
        advertised, actually_initialized
    );

    let mut request2 = [0u8; 4096];
    let fixed = fixed_lend_len(&s, &mut request2);
    assert!(fixed <= request2.len(), "fix invariant broken");
    println!("FIX OK: clamped lend length = {}", fixed);
}
