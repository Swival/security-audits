# Pushpin audit-findings — proofs of concept

One PoC per finding under `audit-findings/`. Each subdirectory builds and
runs in isolation. The Rust PoCs use `cargo run --release`; the C++ PoCs use
`make run`.

The Rust ones (001, 012) link against the same crates pushpin uses
(`httparse`, `libc`) and exercise the standard-library calls and parsing
loop pulled directly from `src/connmgr/server.rs` and
`src/core/http1/protocol.rs` respectively.

The C++ ones (007, 015, 022, 023, 024, 030) replicate the vulnerable function
bodies with `std::string` / `std::vector` stand-ins for `QString` /
`QByteArray`. Each PoC's source comments cite the affected lines in the
upstream Pushpin sources so you can compare against the unpatched code.

| ID  | File                                              | Vulnerable code                            | Class                                |
| --- | ------------------------------------------------- | ------------------------------------------ | ------------------------------------ |
| 001 | `001-unix-socket/`                                | `src/connmgr/server.rs:2001`               | Unix-socket bind-before-chmod race   |
| 007 | `007-sockjs-frames/`                              | `src/proxy/sockjssession.cpp:655`          | SockJS fragment DoS                  |
| 012 | `012-content-length/`                             | `src/core/http1/protocol.rs:1128`          | Conflicting Content-Length smuggling |
| 015 | `015-jsonp-callback/`                             | `src/proxy/requestsession.cpp:535`         | JSONP callback JS injection          |
| 022 | `022-instruct-headers/`                           | `src/handler/instruct.cpp:600`             | grip-instruct header CRLF            |
| 023 | `023-instruct-reason/`                            | `src/handler/instruct.cpp:568`             | grip-instruct reason CRLF            |
| 024 | `024-grip-status-reason/`                         | `src/handler/instruct.cpp:242`             | Grip-Status reason CRLF              |
| 030 | `030-cors-reflect/`                               | `src/core/cors.cpp:91-100`                 | CORS reflection + credentials        |

## Running everything

    ./run-all.sh

Each PoC exits 0 on successful reproduction, 1 otherwise.
