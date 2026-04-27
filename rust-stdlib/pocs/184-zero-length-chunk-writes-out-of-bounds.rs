// Bug: FilterMap::next_chunk::<0> calls copy_nonoverlapping into guard.array.as_mut_ptr().add(0)
//      with a destination of length zero, writing past the array.
// Expected: next_chunk::<0>() returns Ok([]) without writing.
// Observed: Out-of-bounds write of size_of::<Item>() bytes; large payloads crash with Bus error.
// Build: rustc 184-zero-length-chunk-writes-out-of-bounds.rs -o /tmp/poc184
// Run:   /tmp/poc184

#![feature(iter_next_chunk)]

fn main() {
    let mut it = core::iter::once(()).filter_map(|_| Some([0xAAu8; 4096]));
    let _ = it.next_chunk::<0>();
}
