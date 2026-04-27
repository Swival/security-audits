// Bug: Xous TcpListener::accept ignores the valid-length returned by lend_mut.
//      For a successful response with valid < 22, it parses fields up to raw[20..22]
//      out of zero-initialized buffer bytes, producing fabricated peer metadata.
// Expected: reject success responses with valid < 22 as InvalidData.
// Observed: PoC reproduces the field parser; a 4-byte response yields 0.0.0.0:0.
// Build/run: rustc 042-accept-ignores-response-length.rs -o /tmp/poc042 && /tmp/poc042
// Note: real target = riscv32imac-unknown-xous-elf.

fn buggy_parse_accept(raw: &[u8; 4096], _valid: usize) -> Option<(u16, [u8; 4], u16)> {
    if raw[0] != 0 {
        return None;
    }
    let stream_fd = u16::from_le_bytes(raw[1..3].try_into().unwrap());
    let af = raw[3];
    if af != 4 {
        return None;
    }
    let ip = [raw[4], raw[5], raw[6], raw[7]];
    let port = u16::from_le_bytes(raw[20..22].try_into().unwrap());
    Some((stream_fd, ip, port))
}

fn main() {
    let mut raw = [0u8; 4096];
    raw[0] = 0;
    raw[1] = 0x42;
    raw[2] = 0x00;
    raw[3] = 4;
    let valid = 4usize;

    let parsed = buggy_parse_accept(&raw, valid).expect("parse should succeed buggy");
    let (fd, ip, port) = parsed;

    println!("valid_bytes={valid} parsed_fd={fd} ip={ip:?} port={port}");
    assert_eq!(ip, [0, 0, 0, 0]);
    assert_eq!(port, 0);
    assert!(valid < 22, "patch requires valid >= 22 before parsing");
    println!(
        "BUG TRIGGERED: a {valid}-byte response was accepted and produced fabricated peer 0.0.0.0:0"
    );
}
