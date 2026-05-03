// PoC for finding 030: src/core/cors.cpp:91-101.
//
// Cors::applyCorsHeaders unconditionally adds
//
//     Access-Control-Allow-Credentials: true
//
// and then, when the response has no Access-Control-Allow-Origin yet, copies
// the request Origin verbatim (or "*" if the request has no Origin). The
// combination "ACAC: true" + reflected attacker Origin tells the browser that
// the attacker's origin is trusted to make credentialed cross-origin reads.
//
// This PoC reproduces the behavior with std::string-based stand-ins for
// HttpHeaders. The control flow mirrors the C++ source line by line; only
// QByteArray/CowByteArray/Qt-specific calls are replaced with their plain
// equivalents.

#include <cstdio>
#include <string>
#include <vector>
#include <utility>

using Header = std::pair<std::string, std::string>;
using Headers = std::vector<Header>;

static bool contains(const Headers &h, const std::string &name) {
    for (const auto &kv : h)
        if (kv.first == name)
            return true;
    return false;
}

static std::string get(const Headers &h, const std::string &name) {
    for (const auto &kv : h)
        if (kv.first == name)
            return kv.second;
    return std::string();
}

// Mirrors src/core/cors.cpp:51-105 (the relevant prefix).
static void applyCorsHeaders(const Headers &requestHeaders, Headers *responseHeaders) {
    // src/core/cors.cpp:91
    if (!contains(*responseHeaders, "Access-Control-Allow-Credentials"))
        responseHeaders->push_back({"Access-Control-Allow-Credentials", "true"});

    // src/core/cors.cpp:94
    if (!contains(*responseHeaders, "Access-Control-Allow-Origin")) {
        std::string origin = get(requestHeaders, "Origin");
        if (origin.empty())
            origin = "*";
        // src/core/cors.cpp:100 -- reflects the attacker's value.
        responseHeaders->push_back({"Access-Control-Allow-Origin", origin});
    }
}

int main() {
    Headers req = {
        {"Origin", "https://attacker.example"},
        {"Cookie", "session=victim-cookie"},
    };
    Headers resp;

    applyCorsHeaders(req, &resp);

    std::string aco = get(resp, "Access-Control-Allow-Origin");
    std::string acac = get(resp, "Access-Control-Allow-Credentials");

    std::printf("Access-Control-Allow-Origin     : %s\n", aco.c_str());
    std::printf("Access-Control-Allow-Credentials: %s\n", acac.c_str());

    bool vulnerable = aco == "https://attacker.example" && acac == "true";

    if (vulnerable) {
        std::puts("\nRESULT: vulnerable. The attacker-controlled Origin was reflected");
        std::puts("        alongside Access-Control-Allow-Credentials: true. Browsers");
        std::puts("        will permit credentialed cross-origin reads from this origin.");
        return 0;
    }

    std::puts("\nRESULT: did not reproduce");
    return 1;
}
