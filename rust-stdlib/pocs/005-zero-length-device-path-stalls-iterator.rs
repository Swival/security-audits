// 005-zero-length-device-path-stalls-iterator
//
// Bug: library/std/src/sys/pal/uefi/helpers.rs `DevicePathIterator::next`
// advances by `DevicePathNode::length()`. A malformed non-end device-path
// node with length=0 makes `next_node()` return the same pointer while
// `is_end()` stays false, so the iterator yields the same node forever.
//
// Expected: malformed undersized nodes (length < device_path::Protocol header
// size = 4) terminate iteration.
// Observed: this PoC reproduces the iterator using the same is_end()/length()
// logic with a hand-crafted node that has node_type != END_TYPE and
// length = 0. The pre-patch loop never makes progress; we cap the demo at
// 1_000_000 iterations and observe that the iterator still yields the same
// node every time. The patched constructor + next() detect length < 4 and
// stop after the first yield.
//
// Build/run:
//   rustc 005-zero-length-device-path-stalls-iterator.rs -o /tmp/poc005
//   /tmp/poc005

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Node { node_type: u8, sub_type: u8, length: [u8; 2] }

const END_TYPE: u8 = 0x7f;
const HEADER_SIZE: u16 = 4;

unsafe fn next_node(p: *const Node) -> *const Node {
    let len = u16::from_le_bytes((*p).length);
    (p as *const u8).add(len as usize) as *const Node
}
unsafe fn is_end(p: *const Node) -> bool { (*p).node_type == END_TYPE }
unsafe fn length(p: *const Node) -> u16 { u16::from_le_bytes((*p).length) }

unsafe fn buggy_iter(start: *const Node, cap: usize) -> usize {
    let mut cur = if is_end(start) { None } else { Some(start) };
    let mut count = 0usize;
    while let Some(n) = cur {
        count += 1;
        if count > cap { return count; }
        let nxt = next_node(n);
        cur = if is_end(nxt) { None } else { Some(nxt) };
    }
    count
}

unsafe fn patched_iter(start: *const Node, cap: usize) -> usize {
    let mut cur = if is_end(start) || length(start) < HEADER_SIZE { None } else { Some(start) };
    let mut count = 0usize;
    while let Some(n) = cur {
        count += 1;
        if count > cap { return count; }
        let nxt = next_node(n);
        cur = if is_end(nxt) || length(nxt) < HEADER_SIZE { None } else { Some(nxt) };
    }
    count
}

fn main() {
    let bad = Node { node_type: 0x01, sub_type: 0x01, length: [0, 0] };
    let p = &bad as *const Node;

    let buggy_count = unsafe { buggy_iter(p, 1_000_000) };
    println!("pre-patch yielded:  {} (capped, iterator never terminates)", buggy_count);
    assert!(buggy_count > 1_000_000);

    let patched_count = unsafe { patched_iter(p, 1_000_000) };
    println!("patched yielded:    {}", patched_count);
    assert_eq!(patched_count, 0);
}
