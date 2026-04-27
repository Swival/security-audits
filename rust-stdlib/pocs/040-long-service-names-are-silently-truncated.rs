// Bug: Xous service-name connection helpers silently truncate names longer than
//      NAME_MAX_LENGTH (64 bytes), so a caller asking for "PREFIX64bytes...EXTRA"
//      can get connected to "PREFIX64bytes" instead.
// Expected: Reject names longer than NAME_MAX_LENGTH bytes.
// Observed: PoC mimics the truncating ConnectRequest constructor and shows that
//           an overlong name is silently coerced to its 64-byte prefix.
// Build/run: rustc 040-long-service-names-are-silently-truncated.rs -o /tmp/poc040 && /tmp/poc040
// Note: target = riscv32imac-unknown-xous-elf in real code; behaviour mirrored on host.

const NAME_MAX_LENGTH: usize = 64;

struct ConnectRequest {
    data: [u8; 128],
}

impl ConnectRequest {
    fn new(name: &str) -> Self {
        let mut cr = ConnectRequest { data: [0u8; 128] };
        let name_bytes = name.as_bytes();
        for (&src_byte, dest_byte) in name_bytes.iter().zip(&mut cr.data[0..NAME_MAX_LENGTH]) {
            *dest_byte = src_byte;
        }
        cr
    }
}

fn buggy_connect_with_name_impl(name: &str) -> (Vec<u8>, usize) {
    let request = ConnectRequest::new(name);
    let advertised_len = name.len().min(NAME_MAX_LENGTH);
    (request.data[..advertised_len].to_vec(), advertised_len)
}

fn main() {
    let prefix: String = "A".repeat(NAME_MAX_LENGTH);
    let overlong = format!("{prefix}_DIFFERENT_SERVICE_SUFFIX");

    let (sent, sent_len) = buggy_connect_with_name_impl(&overlong);

    assert_eq!(sent_len, NAME_MAX_LENGTH);
    assert_eq!(sent, prefix.as_bytes());
    assert_ne!(overlong.as_bytes(), &sent[..]);

    println!(
        "input_len={} sent_len={} sent_matches_prefix={} input_eq_sent={}",
        overlong.len(),
        sent_len,
        sent == prefix.as_bytes(),
        overlong.as_bytes() == &sent[..]
    );
    println!("BUG TRIGGERED: overlong name silently truncated to 64-byte prefix.");
}
