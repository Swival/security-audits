// Bug: Xous Thread::new computes (stack_size + 4095) & !4095 without overflow
//      checking. For unaligned stack_size > usize::MAX - 4095, the addition
//      overflows: panic in checked builds, wraps to 0 in release.
// Expected: checked_add with InvalidInput error.
// Observed: with -C overflow-checks=on the buggy line panics; with -C overflow-checks=off
//           the rounded size becomes 0.
// Build/run:
//   rustc -C overflow-checks=on  043-stack-rounding-addition-overflows.rs -o /tmp/poc043_chk && /tmp/poc043_chk
//   rustc -C overflow-checks=off 043-stack-rounding-addition-overflows.rs -o /tmp/poc043_rel && /tmp/poc043_rel
// Note: real target = riscv32imac-unknown-xous-elf.

const MIN_STACK_SIZE: usize = 4096;

fn buggy_round(stack: usize) -> usize {
    let mut stack_size = std::cmp::max(stack, MIN_STACK_SIZE);
    if (stack_size & 4095) != 0 {
        stack_size = stack_size.wrapping_add(4095) & !4095;
    }
    stack_size
}

fn buggy_round_checked_arith(stack: usize) -> usize {
    let mut stack_size = std::cmp::max(stack, MIN_STACK_SIZE);
    if (stack_size & 4095) != 0 {
        stack_size = (stack_size + 4095) & !4095;
    }
    stack_size
}

fn main() {
    let bad = usize::MAX - 1;
    let wrapped = buggy_round(bad);
    println!("input=0x{bad:x} wrapped_rounded=0x{wrapped:x}");
    assert_eq!(wrapped, 0, "wrapping form must collapse to 0");
    println!("BUG TRIGGERED (release semantics): rounded stack collapsed to 0.");

    let panicked =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| buggy_round_checked_arith(bad)))
            .is_err();

    if cfg!(debug_assertions) {
        assert!(panicked, "debug build must panic on overflowing add");
        println!("BUG TRIGGERED (debug semantics): unchecked add panicked.");
    } else {
        println!("release build: panic-form unobservable without overflow-checks=on (panicked={panicked})");
    }
}
