// Bug: Xous TcpStream::write decodes the byte count from send_request.raw[4..8] returned by
//      net_server and returns it without clamping to buf_len = min(4096, buf.len()); a malformed
//      success response can therefore make Write::write return n > buf.len(), causing write_all
//      to skip data or panic when slicing buf[n..].
// Expected: clamp returned count to buf_len before reporting.
// Observed: this PoC mimics the buggy decode and demonstrates write_all panicking on buf[n..].
// Build/run:
//   rustc /Users/j/src/swival-audits/rust-stdlib/pocs/023-write-reports-excess-bytes.rs \
//     -o /tmp/poc023 && /tmp/poc023 ; echo exit=$?
// Cross-build (metadata): rustc --target=riscv32imac-unknown-xous-elf --emit=metadata --edition=2021 ...

struct SendRequest { raw: [u8; 4096] }

fn buggy_write(buf: &[u8], server_returned_count: u32) -> usize {
    let mut send_request = SendRequest { raw: [0u8; 4096] };
    let buf_len = send_request.raw.len().min(buf.len());
    send_request.raw[..buf_len].copy_from_slice(&buf[..buf_len]);
    let bytes = server_returned_count.to_le_bytes();
    send_request.raw[4..8].copy_from_slice(&bytes);
    u32::from_le_bytes([
        send_request.raw[4],
        send_request.raw[5],
        send_request.raw[6],
        send_request.raw[7],
    ]) as usize
}

fn main() {
    let buf = vec![0xAAu8; 100];
    let reported = buggy_write(&buf, 0xFFFF_FFFF);
    println!("write returned reported = {reported}, buf.len() = {}", buf.len());
    let panic_check = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _slice = &buf[reported..];
    }));
    match panic_check {
        Err(_) => {
            println!("BUG TRIGGERED: write_all-style buf[n..] panics with n > buf.len()");
            std::process::exit(0);
        }
        Ok(_) => {
            eprintln!("UNEXPECTED: no panic");
            std::process::exit(1);
        }
    }
}
