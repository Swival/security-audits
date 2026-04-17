# Accepted connection tracking lacks a concurrency bound

## Classification
- Type: resource lifecycle bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/wasix/src/runners/dproxy/runner.rs:85`

## Summary
Accepted inbound TCP connections were added to `FuturesUnordered` without any cap on concurrent live sessions. An attacker who can reach the listener can open and hold many connections, causing unbounded growth in active connection futures, sockets, and runtime state until memory, file descriptor, or scheduler capacity is exhausted.

## Provenance
- Verified from the provided reproducer and source inspection
- Scanner reference: https://swival.dev

## Preconditions
- Attacker can open many TCP connections to the configured listener address
- Attacker can keep those connections alive long enough to accumulate active sessions

## Proof
At `lib/wasix/src/runners/dproxy/runner.rs:85`, the listener loop accepts each inbound socket and immediately wraps it for graceful shutdown handling, then pushes the resulting connection future into `FuturesUnordered`. There was no check on the number of currently tracked live connections before admitting another one.

This means completed futures are eventually drained, but active connections remain unbounded. Because no listener-side idle timeout or concurrency gate exists in this path, a client can repeatedly connect and hold sockets open, forcing one live Hyper connection future and associated socket/runtime state per connection.

The issue is reachable on each successful `listener.accept()` for the configured bind address. The default bind target is loopback, but deployment configuration can expose a broader address; the bug remains valid wherever the listener is reachable.

## Why This Is A Real Bug
This is a direct resource exhaustion condition on an externally reachable accept loop. The absence of any admission control means resource usage scales linearly with attacker-held live connections rather than with legitimate service capacity. Even though finished futures are removed correctly, the implementation still allows the set of active connections to grow without bound, which is sufficient to exhaust process resources.

## Fix Requirement
Enforce a maximum concurrent connection limit before adding a new accepted connection to the tracked set. Once the limit is reached, either reject new connections or wait until capacity becomes available before accepting more.

## Patch Rationale
The patch adds a concurrency bound in the accept path so the runner cannot accumulate unlimited live connection futures. This directly addresses the exhaustion vector at the point of admission and aligns connection tracking with a finite resource budget.

## Residual Risk
None

## Patch
- `033-accepted-connections-are-tracked-without-any-concurrency-lim.patch` adds a maximum concurrent connection guard in `lib/wasix/src/runners/dproxy/runner.rs` before pushing accepted connections into the in-flight futures set
- The change preserves normal connection handling while preventing unbounded growth of active tracked sessions