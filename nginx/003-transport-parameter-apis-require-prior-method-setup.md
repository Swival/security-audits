# Transport parameter APIs require prior method setup

## Classification
- Type: invariant violation
- Severity: medium
- Confidence: certain

## Affected Locations
- `src/event/quic/ngx_event_quic_openssl_compat.c:456`
- `src/event/quic/ngx_event_quic_openssl_compat.c:481`

## Summary
`SSL_set_quic_transport_params()` and `SSL_get_peer_quic_transport_params()` assume QUIC compat state is already initialized by `SSL_set_quic_method()`. When either API is called first on a QUIC `SSL *`, `qc->compat` is `NULL` and the implementation dereferences it, causing a process crash.

## Provenance
- Verified from the provided finding and reproducer summary
- Reproduced against the compat implementation in `src/event/quic/ngx_event_quic_openssl_compat.c`
- Scanner reference: https://swival.dev

## Preconditions
- A QUIC `SSL *` is backed by an `ngx_quic_connection_t`
- `SSL_set_quic_transport_params()` or `SSL_get_peer_quic_transport_params()` is invoked before `SSL_set_quic_method()`

## Proof
`SSL_set_quic_transport_params()` resolves `c`, then `qc = ngx_quic_get_connection(c)`, then `com = qc->compat`, and immediately writes through `com->tp` in `src/event/quic/ngx_event_quic_openssl_compat.c:456`. `SSL_get_peer_quic_transport_params()` follows the same pattern for `com->ctp` in `src/event/quic/ngx_event_quic_openssl_compat.c:481`. Only `SSL_set_quic_method()` initializes `qc->compat`, so calling either transport-parameter API first produces a null-pointer dereference and crashes the caller.

## Why This Is A Real Bug
This is a reachable API-level crash in exported QUIC compat functions. The in-tree nginx call flow happens to initialize the method first, but the implementation itself does not enforce that contract. Any embedding caller using the compat API directly can violate the ordering requirement and trigger a local denial of service.

## Fix Requirement
Reject transport-parameter API calls unless both `qc` and `qc->compat` are non-`NULL`, thereby enforcing the required initialization order established by `SSL_set_quic_method()`.

## Patch Rationale
Add explicit guards in both transport-parameter APIs before dereferencing compat state. This preserves the existing initialization model, converts the crash into a clean API failure, and makes the ordering requirement enforceable at the boundary where misuse occurs.

## Residual Risk
None

## Patch
Patched in `003-transport-parameter-apis-require-prior-method-setup.patch` by adding null checks for `qc` and `qc->compat` in:
- `src/event/quic/ngx_event_quic_openssl_compat.c:456`
- `src/event/quic/ngx_event_quic_openssl_compat.c:481`

The patch makes both APIs fail safely when called before `SSL_set_quic_method()` instead of dereferencing uninitialized compat state.