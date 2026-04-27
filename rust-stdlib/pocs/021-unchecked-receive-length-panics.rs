// Bug: Xous TcpStream::read_or_peek trusts attacker-controlled `length` from net_server's
//      `lend_mut` reply and uses it to slice a fixed 4096-byte receive buffer; length > 4096
//      panics with an out-of-bounds slice in safe Rust.
// Expected: clamp length to data_to_read (= min(buf.len(), 4096)) before slicing.
// Observed: this reproduces the slice-out-of-bounds panic by mimicking the same slicing.
// Build/run:
//   rustc /Users/j/src/swival-audits/rust-stdlib/pocs/021-unchecked-receive-length-panics.rs \
//     -o /tmp/poc021 && /tmp/poc021 ; echo "exit=$?"
// Cross-build for xous (metadata only):
//   rustc --target=riscv32imac-unknown-xous-elf --emit=metadata --edition=2021 \
//     /Users/j/src/swival-audits/rust-stdlib/pocs/021-unchecked-receive-length-panics.rs

struct ReceiveData { raw: [u8; 4096] }

fn buggy_read_or_peek(buf: &mut [u8], lend_offset: usize, lend_length: usize) -> usize {
    let receive_request = ReceiveData { raw: [0u8; 4096] };
    let _data_to_read = buf.len().min(receive_request.raw.len());
    let offset = lend_offset;
    let length = lend_length;
    if offset != 0 {
        for (dest, src) in buf.iter_mut().zip(receive_request.raw[..length].iter()) {
            *dest = *src;
        }
        return length;
    }
    0
}

fn main() {
    let mut buf = [0u8; 64];
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        buggy_read_or_peek(&mut buf, 1, 5000)
    }));
    match result {
        Err(_) => {
            println!("BUG TRIGGERED: panic on receive_request.raw[..length] with length=5000 > 4096");
            std::process::exit(0);
        }
        Ok(n) => {
            eprintln!("UNEXPECTED: returned {n} without panic");
            std::process::exit(1);
        }
    }
}
