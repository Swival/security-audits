// Bug: Xous TcpStream::read_or_peek returns the server-supplied `length` even when it
//      exceeds buf.len(); zip() bounds the actual copy by buf.len(), producing
//      Read::read returning n > buf.len() and reporting bytes never copied.
// Expected: clamp length to data_to_read (= min(buf.len(), 4096)) before returning.
// Observed: poc returns n=2000 while only buf.len()=64 bytes were ever copied.
// Build/run:
//   rustc /Users/j/src/swival-audits/rust-stdlib/pocs/022-read-reports-uncopied-bytes.rs \
//     -o /tmp/poc022 && /tmp/poc022
// Cross-build (metadata): rustc --target=riscv32imac-unknown-xous-elf --emit=metadata --edition=2021 ...

struct ReceiveData { raw: [u8; 4096] }

fn buggy_read_or_peek(buf: &mut [u8], lend_offset: usize, lend_length: usize) -> usize {
    let mut receive_request = ReceiveData { raw: [0u8; 4096] };
    for i in 0..lend_length.min(4096) {
        receive_request.raw[i] = (i as u8).wrapping_add(0x10);
    }
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
    let n = buggy_read_or_peek(&mut buf, 1, 2000);
    println!("returned n = {n}, buf.len() = {}", buf.len());
    if n > buf.len() {
        println!("BUG TRIGGERED: Read contract violated; reported n > buf.len()");
        std::process::exit(0);
    } else {
        eprintln!("UNEXPECTED: n was clamped");
        std::process::exit(1);
    }
}
