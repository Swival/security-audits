// Bug: System::realloc on SOLID calls libc::realloc on a pointer that
//      System::alloc obtained via libc::memalign when align <= MIN_ALIGN
//      but align > layout.size().
// Target: armv7a-none-eabi (SOLID, target_os = "solid_asp3")
// Expected: realloc must use realloc_fallback for memalign-origin pointers.
// Observed: original branch logic forwards to libc::realloc directly,
//           mismatching the allocator-origin invariant.
// Build: rustc --target=armv7a-none-eabi --emit=metadata --crate-type=lib \
//        102-realloc-used-on-memalign-allocation.rs
// (verification is logical; SOLID toolchain unavailable on host)

#![no_std]
#![allow(dead_code)]

const MIN_ALIGN: usize = 8;

fn alloc_uses_memalign(align: usize, size: usize) -> bool {
    !(align <= MIN_ALIGN && align <= size)
}

fn realloc_uses_realloc_buggy(align: usize, new_size: usize) -> bool {
    align <= MIN_ALIGN && align <= new_size
}

fn realloc_uses_realloc_fixed(align: usize, size: usize, new_size: usize) -> bool {
    align <= MIN_ALIGN && align <= size && align <= new_size
}

#[unsafe(no_mangle)]
pub fn poc() -> bool {
    let align = 8usize;
    let size = 1usize;
    let new_size = 16usize;
    alloc_uses_memalign(align, size) && realloc_uses_realloc_buggy(align, new_size)
        && !realloc_uses_realloc_fixed(align, size, new_size)
}
