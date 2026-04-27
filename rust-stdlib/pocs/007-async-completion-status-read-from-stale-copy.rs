// 007-async-completion-status-read-from-stale-copy
//
// Bug: library/std/src/sys/net/connection/uefi/tcp4.rs `Tcp4::accept` submits
// `&mut listen_token` to firmware and waits on `&mut listen_token.completion_token`,
// but then reads completion status from the stale local `completion_token` copy.
// Firmware writes the real status into `listen_token.completion_token.status`,
// so an asynchronous error completion is missed and the success branch runs
// with an invalid `new_child_handle`.
//
// Expected: failed accept returns Err with the firmware-written error.
// Observed: the pre-patch read returns the unmodified copy's SUCCESS, even
// though the firmware-completed token reports an error. PoC prints:
//     pre-patch is_error: false (BUG: would proceed to construct child)
//     patched   is_error: true
//
// Build/run:
//   rustc 007-async-completion-status-read-from-stale-copy.rs -o /tmp/poc007
//   /tmp/poc007

#[derive(Clone, Copy)]
struct Status(u32);
impl Status {
    const SUCCESS: Status = Status(0);
    const ERROR: Status = Status(0x8000_0000_u32 | 5);
    fn is_error(self) -> bool { (self.0 & 0x8000_0000) != 0 }
}

#[derive(Clone, Copy)]
struct CompletionToken { status: Status }

#[derive(Clone, Copy)]
struct ListenToken { completion_token: CompletionToken, _new_child: usize }

fn firmware_completes_with_error(listen_token: &mut ListenToken) {
    listen_token.completion_token.status = Status::ERROR;
}

fn main() {
    let completion_token = CompletionToken { status: Status::SUCCESS };
    let mut listen_token = ListenToken { completion_token, _new_child: 0 };

    firmware_completes_with_error(&mut listen_token);

    let pre_patch = completion_token.status.is_error();
    let patched = listen_token.completion_token.status.is_error();

    println!("pre-patch is_error: {} (BUG: would proceed to construct child)", pre_patch);
    println!("patched   is_error: {}", patched);

    assert!(!pre_patch);
    assert!(patched);
}
