# Backend route ID accepted without backend validation

## Classification
- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations
- `src/pushpin.rs:113`
- `src/wiggle_abi/req_impl.rs:882`
- `src/wiggle_abi/req_impl.rs:927`

## Summary
The legacy GRIP redirect path forwards a guest-controlled backend identifier into the `pushpin-route` header without confirming that the identifier matches a configured backend. When Pushpin mode is enabled with route-based forwarding, this lets a guest steer the replayed request to an arbitrary configured Pushpin route ID rather than one admitted by Viceroy's backend registry.

## Provenance
- Verified by reproduction against the current codebase and patched locally
- Scanner source: https://swival.dev

## Preconditions
- Attacker controls `backend_name` passed into the legacy `redirect_to_grip_proxy` or `redirect_to_grip_proxy_v2` flow
- Pushpin integration is enabled
- Deployment accepts `pushpin-route` for backend selection

## Proof
- `PushpinRedirectInfo.backend_name` reaches `proxy_through_pushpin` unchanged
- `src/pushpin.rs:113` sets `pushpin-route` from that value via `req.header("pushpin-route", backend_name.to_string())`
- Unlike normal backend-opening paths, the legacy ABI path does not reject unknown backends
- Reproduction confirmed that `src/wiggle_abi/req_impl.rs:882` and `src/wiggle_abi/req_impl.rs:927` enforce `Error::UnknownBackend` in other flows, while the GRIP redirect path does not
- As a result, a guest can select any Pushpin route ID accepted by the deployment, including one absent from Viceroy's configured backend list

## Why This Is A Real Bug
This is not a theoretical header-manipulation concern. The vulnerable behavior changes routing authority: the header controls which Pushpin backend receives the proxied request. The reproduced path is guest-reachable through the legacy hostcalls, and the codebase already establishes the intended security boundary by rejecting unknown backends elsewhere. The GRIP redirect path bypasses that boundary, creating an authorization inconsistency with practical routing impact.

## Fix Requirement
Validate the supplied backend name against configured backend IDs before setting `pushpin-route`, and reject unknown values with the same error behavior used by other backend-selection paths.

## Patch Rationale
The patch restores consistency with the rest of the backend-selection surface by requiring the GRIP redirect path to resolve only known backends before emitting the routing header. This preserves legitimate configured routes while preventing guest-driven selection of undeclared Pushpin route IDs.

## Residual Risk
None

## Patch
- Patched in `023-backend-name-injected-into-routing-header.patch`
- The fix adds backend existence validation on the legacy GRIP redirect path before `proxy_through_pushpin` applies `pushpin-route`
- Unknown backend names now fail closed instead of being forwarded to Pushpin as routing directives