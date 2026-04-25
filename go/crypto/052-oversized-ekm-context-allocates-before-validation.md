# Oversized EKM Context Allocates Before Validation

## Classification

Validation gap, low severity. Confidence: certain.

## Affected Locations

`src/crypto/tls/prf.go:267`

## Summary

`ExportKeyingMaterial` in the TLS 1.0-1.2 exporter path allocates a seed buffer using `len(context)` before checking whether the context length is valid. An oversized context is ultimately rejected, but only after forcing an avoidable allocation proportional to attacker-controlled input size.

## Provenance

Verified from the supplied finding and reproduced locally. Source: Swival Security Scanner, https://swival.dev

## Preconditions

Caller can pass an oversized non-nil EKM context to `ConnectionState.ExportKeyingMaterial`.

## Proof

The TLS 1.0-1.2 exporter closure installed by `ekmFromMasterSecret` computes:

- `seedLen` including `2 + len(context)`
- `seed := make([]byte, 0, seedLen)`
- only then checks `if len(context) >= 1<<16`

Therefore, a context that will return `context too long` still allocates a backing array sized roughly as:

```text
len(clientRandom) + len(serverRandom) + 2 + len(context)
```

The reproducer confirmed this path and showed an additional allocation of approximately 268 MiB when using a 256 MiB context before the function returned the expected error.

This behavior is limited to the TLS 1.0-1.2 exporter path in `src/crypto/tls/prf.go`; TLS 1.3 uses a separate exporter implementation in `src/crypto/tls/key_schedule.go`.

## Why This Is A Real Bug

The function validates the context length too late. The rejected input still affects allocation size, creating avoidable memory pressure on an error path. Since the context is caller-controlled and the allocation occurs before validation, the behavior is reachable and deterministic.

## Fix Requirement

Validate `len(context) >= 1<<16` before computing `seedLen` or allocating `seed`.

## Patch Rationale

The patch moves the oversized-context check ahead of the seed length calculation and allocation. This preserves the existing error behavior while preventing rejected contexts from influencing allocation size.

## Residual Risk

None

## Patch

`052-oversized-ekm-context-allocates-before-validation.patch`