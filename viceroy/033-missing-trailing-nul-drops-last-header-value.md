# Missing trailing NUL drops last header value

## Classification
- Type: data integrity bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `src/wiggle_abi/headers.rs:114`

## Summary
`values_set` parses guest-provided header values by splitting the input buffer on `0` and then always discarding the final segment. That behavior is only correct when the buffer is NUL-terminated. When the caller provides a valid separator-delimited buffer without a trailing NUL, the last real header value is dropped, and the host silently stores a truncated value set.

## Provenance
- Verified from the provided reproducer and source review
- Swival Security Scanner: https://swival.dev

## Preconditions
- `values_set` receives `values` bytes without a trailing NUL

## Proof
The ABI contract describes the input as multiple values separated by `\0`, but does not require a final terminator; see `wasm_abi/compute-at-edge-abi/compute-at-edge.witx:325` and `wasm_abi/compute-at-edge-abi/compute-at-edge.witx:902`.

The adapter layer forwards the caller-controlled slice unchanged into the host implementation, with no trailing-NUL normalization; see `wasm_abi/adapter/src/fastly/core.rs:1941` and `wasm_abi/adapter/src/fastly/core.rs:2838`.

In `values_set`, the buffer is split on `0`, then `iter.next_back()` is called unconditionally to remove the assumed empty terminator segment at `src/wiggle_abi/headers.rs:114`. For non-terminated input, that segment is not empty; it is the final real header value.

Concrete example:
```text
values = b"foo\0bar"
split => ["foo", "bar"]
next_back() drops "bar"
stored values => only ["foo"]
```

The function later removes existing values and appends only the parsed set at `src/wiggle_abi/headers.rs:157`, making the truncation silent and destructive.

## Why This Is A Real Bug
This is not a malformed-input rejection path; it is silent state corruption. The documented interface permits separator-delimited lists, and the adapter does not enforce a trailing terminator. As a result, valid caller-controlled input can cause the last header value to be lost while the operation still succeeds. That is a direct data-integrity failure.

## Fix Requirement
Only discard the final split segment when `values_bytes` actually ends with `0`. If there is no trailing NUL, retain the last segment as a real header value.

## Patch Rationale
The patch makes terminator removal conditional on the actual buffer encoding instead of an unconditional assumption. This preserves existing behavior for correctly terminated buffers while preventing truncation for separator-delimited buffers that omit the final NUL.

## Residual Risk
None

## Patch
Patched in `033-missing-trailing-nul-drops-last-header-value.patch`.