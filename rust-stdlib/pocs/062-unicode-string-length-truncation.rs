// Bug: UnicodeStrRef::new on Windows casts usize byte lengths into u16 fields of
//      UNICODE_STRING without checking range. For slices > u16::MAX/2 code units the
//      cast truncates.
// Expected: oversized inputs are rejected before constructing UNICODE_STRING.
// Observed: pre-patch, casts wrap. 32768 u16 -> 65536 bytes -> Length=0,
//           32771 u16 -> 65542 bytes -> Length=6.
// Build/run: rustc 062-unicode-string-length-truncation.rs -o /tmp/poc062 && /tmp/poc062

fn buggy_lengths(slice_len: usize) -> (u16, u16) {
    let bytes = slice_len * 2;
    let max_len = bytes;
    (bytes as u16, max_len as u16)
}

fn main() {
    let (l1, m1) = buggy_lengths(32768);
    assert_eq!((l1, m1), (0, 0));
    let (l2, m2) = buggy_lengths(32771);
    assert_eq!((l2, m2), (6, 6));
    println!("triggered: 32768 -> ({}, {}); 32771 -> ({}, {}) (truncated)", l1, m1, l2, m2);
}
