// Bug: Clamp(..=end).get on empty slice computes slice.len() - 1, underflowing usize.
// Expected: Returns the clamped empty prefix Some(&[]).
// Observed: Panic in debug ("attempt to subtract with overflow"); silent wrap in release.
// Build: rustc -C overflow-checks=on 181-inclusive-rangeto-clamp-get-underflows-on-empty-slice.rs -o /tmp/poc181
// Run:   /tmp/poc181

use std::cmp;

fn clamp_get(end: usize, slice: &[u8]) -> Option<&[u8]> {
    (..=cmp::min(end, slice.len() - 1)).get(slice)
}

trait SliceGet<T> {
    fn get(self, slice: &[T]) -> Option<&[T]>;
}

impl<T> SliceGet<T> for std::ops::RangeToInclusive<usize> {
    fn get(self, slice: &[T]) -> Option<&[T]> {
        slice.get(..=self.end)
    }
}

fn main() {
    let empty: &[u8] = &[];
    let _ = clamp_get(0, empty);
    println!("unreachable: should have panicked on len()-1");
}
