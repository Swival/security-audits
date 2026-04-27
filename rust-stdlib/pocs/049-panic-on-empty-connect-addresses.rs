// Bug: Motor TcpStream::connect calls
//        addr.to_socket_addrs()?.next().unwrap()
//      so an empty `&[SocketAddr]` panics instead of returning io::Error.
// Expected: ok_or(io::Error::NO_ADDRESSES) before calling into the runtime.
// Observed: PoC mirrors the unwrap pattern with the same iterator semantics.
// Build/run: rustc 049-panic-on-empty-connect-addresses.rs -o /tmp/poc049 && /tmp/poc049
// Note: real target = x86_64-unknown-motor.

use std::net::{SocketAddr, ToSocketAddrs};

fn buggy_connect<A: ToSocketAddrs>(addr: A) {
    let _addr = addr.to_socket_addrs().unwrap().next().unwrap();
}

fn main() {
    let addrs: &[SocketAddr] = &[];
    let panicked = std::panic::catch_unwind(|| buggy_connect(addrs)).is_err();
    assert!(panicked, "expected panic on empty address slice");
    println!("BUG TRIGGERED: TcpStream::connect-style unwrap panicked on empty addresses.");
}
