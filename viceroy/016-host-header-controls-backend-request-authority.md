# Host Header Overrides Backend Authority

## Classification
- Type: trust-boundary violation
- Severity: medium
- Confidence: certain

## Affected Locations
- `src/upstream.rs:190`

## Summary
Client-controlled `Host` is trusted when forwarding to a backend that does not set `override_host`. The forwarding path derives the outbound request authority and `Host` header from the inbound header instead of the configured backend, so the backend receives attacker-chosen authority metadata while the connector still dials the configured backend endpoint.

## Provenance
- Verified from source and reproduced by reasoning against the forwarding path in `src/upstream.rs:190`
- Reproducer corroborated by existing integration expectations in `cli/tests/integration/upstream.rs:132`
- Scanner provenance: `https://swival.dev`

## Preconditions
- Backend has no `override_host`
- Attacker controls the inbound request `Host` header

## Proof
`canonical_host_header` prefers `original_headers[HOST]` over `backend.uri.host()` when no override is configured. `send_request` passes that value into `canonical_uri`, replacing the outbound URI authority, and then writes the same value back into the outbound `Host` header before dispatch. `BackendConnector` still connects to `backend.uri`, so the socket destination remains fixed, but the backend-visible request authority is attacker-chosen.

## Why This Is A Real Bug
This crosses a trust boundary: untrusted client routing metadata is forwarded as trusted backend authority. Backends commonly use `Host` or URI authority for virtual-host selection, tenant routing, policy enforcement, and absolute URL generation. That makes host-based misrouting and policy confusion reachable on ordinary forwarded requests whenever `override_host` is unset.

## Fix Requirement
Always derive outbound URI authority and `Host` from backend configuration by default. Only use an alternate host when there is an explicit trusted override configuration.

## Patch Rationale
The patch in `016-host-header-controls-backend-request-authority.patch` removes client `Host` as the default source for backend-facing authority. It makes the configured backend host authoritative unless an explicit override is present, preserving intended override behavior while eliminating attacker control of backend-visible authority.

## Residual Risk
None

## Patch
- File: `016-host-header-controls-backend-request-authority.patch`
- Effect: backend-facing URI authority and `Host` header now come from backend configuration unless an explicit trusted override is configured