// 004-stale-handle-count-sets-vec-length
//
// Bug: library/std/src/sys/pal/uefi/helpers.rs `locate_handles` reads the
// required byte length from a first LocateHandle call (sizing), allocates,
// calls LocateHandle a second time, and then unsafely sets the Vec length
// from the FIRST call's count even though UEFI updated `buf_len` to the
// (possibly smaller) bytes actually written by the second call. When the
// handle database shrinks between calls, set_len exposes uninitialized
// trailing slots as "handles".
//
// Expected: only handles actually written by the second call are exposed.
// Observed: this PoC simulates the same control flow with a fake LocateHandle.
// First call reports 4 handles; before the second call the database shrinks
// to 1 handle. Pre-patch logic does `set_len(num_of_handles=4)` and the next
// 3 entries are the original (uninitialized-style) MaybeUninit fill bytes,
// here visible as the sentinel 0xAAAAAAAA we pre-stamp into the buffer.
// The PoC prints these stale "handles":
//     handles: [0x1, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa]
//
// The patched logic uses buf_len from the second call and prints:
//     handles (patched): [0x1]
//
// Build/run:
//   rustc 004-stale-handle-count-sets-vec-length.rs -o /tmp/poc004
//   /tmp/poc004

use std::mem::{size_of, MaybeUninit};

type Handle = usize;

#[derive(Default)]
struct FakeUefi { call: u32 }

impl FakeUefi {
    fn locate_handle(&mut self, buf: *mut Handle, buf_len: &mut usize) -> Result<(), &'static str> {
        self.call += 1;
        match self.call {
            1 => { *buf_len = 4 * size_of::<Handle>(); Err("buffer too small") }
            2 => {
                unsafe { buf.write(0x1usize) };
                *buf_len = 1 * size_of::<Handle>();
                Ok(())
            }
            _ => unreachable!(),
        }
    }
}

fn buggy(uefi: &mut FakeUefi) -> Vec<Handle> {
    let mut buf_len: usize = 0;
    let _ = uefi.locate_handle(std::ptr::null_mut(), &mut buf_len);
    let num_of_handles = buf_len / size_of::<Handle>();
    let mut buf: Vec<MaybeUninit<Handle>> = Vec::with_capacity(num_of_handles);
    for _ in 0..num_of_handles {
        buf.push(MaybeUninit::new(0xaaaaaaaaaaaaaaaa));
    }
    let mut buf: Vec<Handle> = unsafe { std::mem::transmute(buf) };
    unsafe { buf.set_len(0) };
    let _ = uefi.locate_handle(buf.as_mut_ptr(), &mut buf_len);
    unsafe { buf.set_len(num_of_handles) };
    buf
}

fn patched(uefi: &mut FakeUefi) -> Vec<Handle> {
    let mut buf_len: usize = 0;
    let _ = uefi.locate_handle(std::ptr::null_mut(), &mut buf_len);
    let num_of_handles = buf_len / size_of::<Handle>();
    let mut buf: Vec<MaybeUninit<Handle>> = Vec::with_capacity(num_of_handles);
    for _ in 0..num_of_handles {
        buf.push(MaybeUninit::new(0xaaaaaaaaaaaaaaaa));
    }
    let mut buf: Vec<Handle> = unsafe { std::mem::transmute(buf) };
    unsafe { buf.set_len(0) };
    let _ = uefi.locate_handle(buf.as_mut_ptr(), &mut buf_len);
    assert_eq!(buf_len % size_of::<Handle>(), 0);
    unsafe { buf.set_len(buf_len / size_of::<Handle>()) };
    buf
}

fn main() {
    let mut u = FakeUefi::default();
    let v = buggy(&mut u);
    print!("handles:           [");
    for (i, h) in v.iter().enumerate() {
        if i > 0 { print!(", "); }
        print!("{:#x}", h);
    }
    println!("]");

    let mut u = FakeUefi::default();
    let v = patched(&mut u);
    print!("handles (patched): [");
    for (i, h) in v.iter().enumerate() {
        if i > 0 { print!(", "); }
        print!("{:#x}", h);
    }
    println!("]");
}
