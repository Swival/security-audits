// Bug: System::realloc on unix used `layout.align() <= new_size` instead of
//      `layout.align() <= layout.size()`. Pointers from aligned_malloc could be passed
//      to libc::realloc, which is undefined.
// Expected: realloc dispatches based on the original layout that produced the pointer.
// Observed: predicate is sensitive to new_size; for layout (size=1, align=16) and
//      new_size=16 the buggy predicate selects the libc::realloc path, even though
//      `alloc` selected aligned_malloc.
// Build/run: rustc 061-realloc-uses-mismatched-allocation-predicate.rs -o /tmp/poc061 && /tmp/poc061

const MIN_ALIGN: usize = 16;

fn alloc_uses_aligned(size: usize, align: usize) -> bool {
    !(align <= MIN_ALIGN && align <= size)
}

fn realloc_buggy_uses_libc_realloc(size: usize, align: usize, new_size: usize) -> bool {
    align <= MIN_ALIGN && align <= new_size
}

fn realloc_fixed_uses_libc_realloc(size: usize, align: usize, _new_size: usize) -> bool {
    align <= MIN_ALIGN && align <= size
}

fn main() {
    let size = 1usize;
    let align = 16usize;
    let new_size = 16usize;

    assert!(alloc_uses_aligned(size, align), "alloc takes aligned_malloc path");
    assert!(realloc_buggy_uses_libc_realloc(size, align, new_size),
        "buggy realloc dispatches to libc::realloc on an aligned_malloc pointer");
    assert!(!realloc_fixed_uses_libc_realloc(size, align, new_size),
        "fixed realloc keeps the aligned path");
    println!("triggered: alloc=aligned, buggy_realloc=libc::realloc -> family mismatch");
}
