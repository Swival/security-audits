# Untrusted X-Shard Header Controls Backend Shard Selection

## Classification
- Type: trust-boundary violation
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/wasix/src/runners/dproxy/handler.rs:50`
- `lib/wasix/src/runners/dproxy/handler.rs:90`
- `lib/wasix/src/runners/dproxy/handler.rs:93`
- `lib/wasix/src/runners/dproxy/runner.rs:61`
- `lib/wasix/src/runners/dproxy/runner.rs:75`
- `lib/wasix/src/runners/dproxy/runner.rs:87`
- `lib/wasix/src/runners/dproxy/runner.rs:141`

## Summary
The handler trusted the client-controlled `X-Shard` HTTP header to choose the backend shard. Any requester able to reach the listener could steer traffic into an existing stateful shard or supply arbitrary shard IDs that cause additional backend instances to be selected or created.

## Provenance
- Verified from the provided finding and reproducer
- Reference: https://swival.dev

## Preconditions
- An attacker can send HTTP requests to the dproxy handler

## Proof
The request handler read `req.headers().get("X-Shard")`, parsed the value into `Shard::ById(id)`, and otherwise fell back to `Shard::Singleton`. That `shard` value was then passed unchanged into `self.factory.acquire(self, shard).await`.

The reproduced behavior shows the selected shard directly controlled backend acquisition at `lib/wasix/src/runners/dproxy/handler.rs:90` and `lib/wasix/src/runners/dproxy/handler.rs:93`. Because these instances are intentionally stateful, shard choice is state selection.

Reachability is practical. `DProxyRunner` exposes this handler as an HTTP server without authentication middleware, enables permissive CORS, and binds to `127.0.0.1:8000` by default at `lib/wasix/src/runners/dproxy/runner.rs:61`, `lib/wasix/src/runners/dproxy/runner.rs:75`, `lib/wasix/src/runners/dproxy/runner.rs:87`, and `lib/wasix/src/runners/dproxy/runner.rs:141`.

## Why This Is A Real Bug
This is a real trust-boundary failure because a network client was allowed to influence internal backend routing/state selection using an untrusted header. The effect is not cosmetic: shard selection determines which stateful backend context serves the request. An attacker can therefore cause shard/state confusion and can also mint arbitrary shard IDs to increase backend instance creation, creating straightforward resource-exhaustion impact.

## Fix Requirement
Do not trust client-supplied `X-Shard` for backend selection. Ignore the header at this boundary, or only honor shard selection from a separately authenticated and authorized internal source.

## Patch Rationale
The patch removes client control over shard selection in `lib/wasix/src/runners/dproxy/handler.rs` and forces safe server-side shard behavior instead of propagating `X-Shard` into backend acquisition. This directly closes the trust-boundary violation while preserving normal request handling.

## Residual Risk
None

## Patch
- Patch file: `016-untrusted-x-shard-header-controls-backend-shard-selection.patch`