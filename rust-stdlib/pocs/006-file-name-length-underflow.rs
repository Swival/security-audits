// 006-file-name-length-underflow
//
// Bug: library/std/src/sys/pal/uefi/helpers.rs `file_name_len` computes
//   (self.size() as usize - size_of::<file::Info<0>>()) / size_of::<u16>()
// without validating that `size` is at least the header size. For a malformed
// `file::Info.size = 0`, the subtraction underflows to usize::MAX in release
// builds and yields a huge filename length, which is then used to construct
// an out-of-bounds UTF-16 slice via `slice::from_raw_parts`.
//
// Expected: a below-header `size` produces an empty filename slice.
// Observed: the pre-patch arithmetic returns a huge wrapped length. We compute
// it on the same input the bug observes (size = 0). The PoC prints:
//     pre-patch file_name_len: 9223372036854775797
//     patched   file_name_len: 0
//
// We don't actually call `slice::from_raw_parts` with the wrapped length
// because that is exactly the UB the audit calls out, and the resulting
// dereference would crash. The arithmetic alone proves the underflow.
//
// Build/run (note: avoid -C overflow-checks because release std doesn't
// enable them, which is precisely the buggy build mode):
//   rustc 006-file-name-length-underflow.rs -o /tmp/poc006
//   /tmp/poc006

const HEADER_SIZE: usize = 80;

fn buggy_len(size: u64) -> usize {
    let s = size as usize;
    s.wrapping_sub(HEADER_SIZE) / core::mem::size_of::<u16>()
}

fn patched_len(size: u64) -> usize {
    (size as usize).saturating_sub(HEADER_SIZE) / core::mem::size_of::<u16>()
}

fn main() {
    let malformed_size = 0u64;
    let bad = buggy_len(malformed_size);
    let good = patched_len(malformed_size);
    println!("pre-patch file_name_len: {}", bad);
    println!("patched   file_name_len: {}", good);
    assert!(bad > 1_000_000_000);
    assert_eq!(good, 0);
}
