// Bug: lookup_host copies at most 4096 query bytes into a fixed buffer but forwards
//      query.as_bytes().len() unmodified to the Xous lend_mut call, advertising more
//      valid bytes than the lent buffer contains.
// Expected: queries longer than 4096 bytes should be rejected with InvalidInput.
// Observed: oversized lengths reach the DNS resolver while only 4096 bytes are mapped.
// Build/run: rustc 141-oversized-dns-query-length-forwarded.rs -o /tmp/poc141 && /tmp/poc141
// Target note: the affected code path is target_os="xous"; this PoC reproduces the
// committed buffer logic on the host to demonstrate the truncation/length mismatch.

struct LookupHostQuery([u8; 4096]);

fn build_query(query: &str) -> (LookupHostQuery, usize) {
    let mut buf = LookupHostQuery([0u8; 4096]);
    for (q, r) in query.as_bytes().iter().zip(buf.0.iter_mut()) {
        *r = *q;
    }
    let advertised_len = query.as_bytes().len();
    (buf, advertised_len)
}

fn main() {
    let query: String = "a".repeat(8000);
    let (buf, advertised) = build_query(&query);
    let actual = buf.0.len();
    println!("query bytes: {}", query.as_bytes().len());
    println!("buffer bytes (lent): {}", actual);
    println!("advertised length forwarded to lend_mut: {}", advertised);
    assert!(advertised > actual, "bug not triggered");
    println!("BUG: advertised {} > lent {}", advertised, actual);
}
