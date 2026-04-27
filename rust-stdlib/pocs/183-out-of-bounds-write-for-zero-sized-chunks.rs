// Bug: Filter::next_chunk_dropless writes to array index 0 before checking N==0,
//      so Filter::next_chunk::<0> performs an out-of-bounds get_unchecked_mut on a
//      zero-length [MaybeUninit<T>; 0] and consumes a source element.
// Expected: next_chunk::<0>() returns Ok([]) and consumes nothing.
// Observed: One source element is consumed; the unchecked write to index 0 of a
//           zero-length array is UB.
// Build: rustc 183-out-of-bounds-write-for-zero-sized-chunks.rs -o /tmp/poc183
// Run:   /tmp/poc183

#![feature(iter_next_chunk)]

fn main() {
    let mut it = [10u8, 20u8].into_iter().filter(|_| true);
    let chunk = it.next_chunk::<0>();
    let next = it.next();
    println!("chunk={:?} next={:?}", chunk, next);
    assert!(matches!(chunk, Ok([])));
    assert_eq!(next, Some(20), "first element was consumed by next_chunk::<0>");
}
