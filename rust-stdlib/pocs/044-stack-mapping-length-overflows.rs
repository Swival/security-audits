// Bug: Xous Thread::new computes mapping length as
//      GUARD_PAGE_SIZE + stack_size + GUARD_PAGE_SIZE without overflow check.
//      A page-aligned stack_size = usize::MAX & !4095 wraps to 0x1000.
// Expected: checked_add chain returning InvalidInput.
// Observed: PoC produces the wrapped 0x1000 mapping length and shows the
//           subsequent slice index becomes [4096..0] (panicking in real code).
// Build/run: rustc -C overflow-checks=off 044-stack-mapping-length-overflows.rs -o /tmp/poc044 && /tmp/poc044
// Note: real target = riscv32imac-unknown-xous-elf.

const GUARD_PAGE_SIZE: usize = 4096;

fn buggy_mapping_length(stack_size: usize) -> usize {
    GUARD_PAGE_SIZE.wrapping_add(stack_size).wrapping_add(GUARD_PAGE_SIZE)
}

fn main() {
    let stack_size = usize::MAX & !4095;
    assert_eq!(stack_size & 4095, 0, "page aligned, skips rounding branch");

    let mapped = buggy_mapping_length(stack_size);
    println!("stack_size=0x{stack_size:x} mapped_length=0x{mapped:x}");
    assert_eq!(mapped, 0x1000, "wrapped to one page");

    let stack_end = GUARD_PAGE_SIZE.wrapping_add(stack_size);
    println!("guard_page_size + stack_size = 0x{stack_end:x}");
    assert_eq!(stack_end, 0);
    let lo = GUARD_PAGE_SIZE;
    let hi = stack_end;
    println!("slice indices for create_thread stack: [{lo}..{hi}]");
    assert!(lo > hi, "slice constructor would panic");
    println!("BUG TRIGGERED: mapping wrapped to 0x1000 and stack slice range became [4096..0]");
}
