# Unlimited FastCGI Header Buffering

## Classification
- Type: vulnerability
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/handler/fastcgi.c:510`

## Summary
A FastCGI upstream can send `FCGI_STDOUT` bytes that never complete an HTTP header block, causing the receiver to keep buffering pre-parse header data without any cumulative limit. This permits unbounded memory growth and denial of service in the worker handling the connection.

## Provenance
- Verified from the provided reproducer and code-path analysis
- Source: Swival Security Scanner - https://swival.dev

## Preconditions
- A FastCGI peer sends header bytes without completing the HTTP header block

## Proof
In `lib/handler/fastcgi.c:510`, the FastCGI response path appends incoming `FCGI_STDOUT` payload into `generator->resp.receiving` while `sent_headers == 0`. Header parsing is attempted with `phr_parse_headers`; when parsing is incomplete, it returns `-2`. In that state, additional bytes are accepted and buffered again on subsequent records, with no maximum-size enforcement before parse completion.

The reproduced path shows this remains reachable across repeated readable events:
- `on_read` rearms I/O after each readable notification in `lib/handler/fastcgi.c:725`
- socket readiness is triggered on arriving TCP data in `include/h2o/socket.h:342`
- `include/h2o/socket.h:349`
- the event-loop read limit is per event, not cumulative, in `lib/common/socket/evloop.c.h:132`
- `lib/common/socket/evloop.c.h:165`
- default per-event cap is 1 MB at `lib/common/socket/evloop.c.h:667`

Impact is denial of service through unbounded buffer growth:
- `h2o_buffer_try_reserve` expands buffers as needed in `lib/common/memory.c:409`
- `lib/common/memory.c:489`
- after 32 MB, buffering can spill into mmap-backed temp files in `lib/common/socket.c:178`
- `lib/common/socket.c:184`
- if allocation ultimately fails, `h2o_buffer_reserve` fatally aborts in `lib/common/memory.c:370`
- `lib/common/memory.c:376`

## Why This Is A Real Bug
The vulnerable state is not bounded by protocol progress, read-event count, or a global pre-header size cap. A malicious or compromised FastCGI upstream can therefore keep the worker accumulating memory or temp-file-backed storage indefinitely simply by dribbling partial header bytes and never finishing the header block. This is a direct denial-of-service condition, and the process may terminate if allocation fails.

## Fix Requirement
Enforce a hard upper bound on buffered FastCGI response bytes before header parsing completes, and abort the upstream response once `resp.receiving->size` exceeds that limit.

## Patch Rationale
The patch in `008-unlimited-header-buffering-before-parse-completes.patch` adds a cumulative size check on pre-parse buffered header data in the FastCGI response handling path. This addresses the bug at the point where growth occurs, prevents attacker-controlled indefinite accumulation across multiple read events, and converts the condition into a controlled upstream failure instead of resource exhaustion.

## Residual Risk
None

## Patch
- File: `008-unlimited-header-buffering-before-parse-completes.patch`
- Behavior change: FastCGI responses that do not complete headers within the configured or enforced pre-parse buffer limit are aborted instead of being buffered indefinitely
- Security effect: prevents unbounded memory and temp-buffer growth from malformed or malicious upstream header streams