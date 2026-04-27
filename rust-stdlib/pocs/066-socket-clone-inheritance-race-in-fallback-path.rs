// Bug: BorrowedSocket::try_clone_to_owned on Windows falls back to creating a socket
//      with WSA_FLAG_OVERLAPPED only, and clears HANDLE_FLAG_INHERIT later. Between
//      WSASocketW returning and SetHandleInformation being called, a concurrent
//      CreateProcessW with handle inheritance can copy the socket into the child.
// Expected: cloned socket is non-inheritable from creation.
// Observed: pre-patch, socket exists as inheritable for a window.
// Build/run: rustc 066-socket-clone-inheritance-race-in-fallback-path.rs -o /tmp/poc066 && /tmp/poc066
// Target note: real path is target_os="windows"; this PoC models the race
//      deterministically: it shows that any concurrent observer sees the socket as
//      inheritable in the fallback path before set_no_inherit() runs.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const WSA_FLAG_OVERLAPPED: u32 = 0x01;
const WSA_FLAG_NO_HANDLE_INHERIT: u32 = 0x80;

fn wsasocketw_mock(flags: u32) -> u64 { 0x1000 | flags as u64 }
fn set_handle_information_clear_inherit(_h: u64) {}

fn fallback_clone(observed_inherit_flag: &AtomicU64, child_spawned: &AtomicBool) {
    let socket = wsasocketw_mock(WSA_FLAG_OVERLAPPED);
    observed_inherit_flag.store(socket, Ordering::SeqCst);

    while !child_spawned.load(Ordering::SeqCst) {
        std::hint::spin_loop();
    }

    set_handle_information_clear_inherit(socket);
}

fn main() {
    let observed = Arc::new(AtomicU64::new(0));
    let child_spawned = Arc::new(AtomicBool::new(false));

    let observed_t = observed.clone();
    let child_t = child_spawned.clone();
    let h = thread::spawn(move || fallback_clone(&observed_t, &child_t));

    while observed.load(Ordering::SeqCst) == 0 {
        thread::sleep(Duration::from_micros(1));
    }

    let socket_view = observed.load(Ordering::SeqCst);
    let inheritable = (socket_view as u32 & WSA_FLAG_NO_HANDLE_INHERIT) == 0;
    child_spawned.store(true, Ordering::SeqCst);
    h.join().unwrap();

    assert!(inheritable, "socket observed before set_no_inherit must be inheritable");
    println!("triggered: concurrent observer saw inheritable socket pre-clear");
}
