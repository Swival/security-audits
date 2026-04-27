// Bug: SOLID's sockaddr_storage is laid out as 16 bytes but sockaddr_in6 needs 28 bytes,
//      so an IPv6 address written into sockaddr_storage overflows the storage object.
// Expected: sockaddr_storage must be at least size_of::<sockaddr_in6>().
// Observed: sockaddr_storage = 16 bytes < sockaddr_in6 = 28 bytes.
// Build/run: rustc 142-sockaddr-storage-too-small-for-ipv6.rs -o /tmp/poc142 && /tmp/poc142
// Target note: layout drawn from library/std/src/sys/pal/solid/abi/sockets.rs (target_os="solid_asp3").

#[repr(C)]
struct SockaddrStorage {
    s2_len: u8,
    ss_family: u8,
    s2_data1: [i8; 2],
    s2_data2: [u32; 3],
}

#[repr(C)]
struct SockaddrIn6 {
    sin6_len: u8,
    sin6_family: u8,
    sin6_port: u16,
    sin6_flowinfo: u32,
    sin6_addr: [u8; 16],
    sin6_scope_id: u32,
}

fn main() {
    let storage = std::mem::size_of::<SockaddrStorage>();
    let in6 = std::mem::size_of::<SockaddrIn6>();
    println!("sockaddr_storage = {} bytes", storage);
    println!("sockaddr_in6     = {} bytes", in6);
    assert!(storage < in6, "bug not triggered");
    println!("BUG: storage too small by {} bytes", in6 - storage);
}
