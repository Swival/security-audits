// Bug: Motor TcpListener::bind unwraps next() on the resolved iterator, so an
//      empty &[SocketAddr] input panics instead of returning io::Error.
// Expected: ok_or_else returning InvalidInput.
// Observed: PoC mirrors the unwrap pattern.
// Build/run: rustc 050-panic-on-empty-listener-bind-addresses.rs -o /tmp/poc050 && /tmp/poc050
// Note: real target = x86_64-unknown-motor.

use std::net::{SocketAddr, ToSocketAddrs};

fn buggy_bind<A: ToSocketAddrs>(addr: A) {
    let _ = addr.to_socket_addrs().unwrap().next().unwrap();
}

fn main() {
    let addrs: &[SocketAddr] = &[];
    let panicked = std::panic::catch_unwind(|| buggy_bind(addrs)).is_err();
    assert!(panicked);
    println!("BUG TRIGGERED: TcpListener::bind-style unwrap panicked on empty addresses.");
}
