# HRR Allows PSK Identity Changes

## Classification

Validation gap, low severity. Confidence: certain.

## Affected Locations

`src/crypto/tls/handshake_server_tls13.go:600`

## Summary

TLS 1.3 HelloRetryRequest handling allowed the second ClientHello to change PSK identities and binders. The HRR change validator checked other ClientHello invariants, but did not compare `pskIdentities` or `pskBinders`, so the changed PSK extension was accepted and later used for resumption.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

TLS 1.3 HRR path with client-supplied PSK identities.

## Proof

The client controls both ClientHellos. After HRR, `doHelloRetryRequest()` calls `illegalClientHelloChange()` before replacing `hs.clientHello`.

`illegalClientHelloChange()` compares versions, cipher suites, curves, ALPN, PSK modes, and other fields, but it does not compare `pskIdentities` or `pskBinders`.

The second ClientHello then reaches `checkForResumption()`, which iterates `hs.clientHello.pskIdentities`, validates binders from `hs.clientHello.pskBinders`, and selects a PSK from the second ClientHello.

Therefore, a client can send one PSK identity before HRR and a different PSK identity after HRR, and the server accepts the changed identity.

## Why This Is A Real Bug

TLS 1.3 HRR requires the second ClientHello to preserve most fields from the first ClientHello, except for specific permitted changes. PSK identity changes are not permitted.

The server already enforces many HRR ClientHello invariants, showing this code path is intended to reject illegal changes. The omission of PSK identity and binder comparison creates a real protocol validation gap.

This is not an obvious key-authentication bypass because the PSK binder is still validated against the HRR transcript. The bug is that the server accepts a PSK extension change that TLS 1.3 requires it to reject.

## Fix Requirement

Reject HRR second ClientHellos that change PSK identities or PSK binders relative to the first ClientHello.

## Patch Rationale

The patch adds explicit comparison of `pskIdentities` and `pskBinders` in the HRR ClientHello change validation path. This keeps PSK extension handling consistent with the existing invariant checks for versions, suites, ALPN, curves, and PSK modes.

## Residual Risk

None

## Patch

`016-hrr-allows-psk-identity-changes.patch`