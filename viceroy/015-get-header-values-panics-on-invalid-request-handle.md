# get_header_values panics on invalid request handle

## Classification
- Type: error-handling bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `src/component/compute/http_req.rs:204`

## Summary
`get_header_values` resolves the guest-supplied request handle with `self.session().request_parts(h.into()).unwrap()`. When the handle is invalid or already closed, `request_parts` returns `Err`, and `unwrap()` panics. This traps host execution instead of returning the declared `types::Error`.

## Provenance
- Verified finding reproduced from Swival Security Scanner results
- Source: https://swival.dev

## Preconditions
- A guest can call `get_header_values` with an invalid request handle

## Proof
- `get_header_values` in `src/component/compute/http_req.rs:204` uses `self.session().request_parts(h.into()).unwrap()`.
- Neighboring request accessors in the same implementation use `?` for the same lookup path, including `get_header_names` and `get_header_value`, showing invalid handles are intended to be surfaced as ordinary errors.
- The equivalent older implementation in `src/wiggle_abi/req_impl.rs:653` also propagates lookup failure with `?`.
- Reproduction path: create a request, close it, then call `request.get-header-values("x", ...)` with the stale handle.
- Result before patch: `request_parts` returns `Err(InvalidRequestHandle)`, `unwrap()` panics, and host execution traps instead of returning the ABI-declared `result<..., error>`.

## Why This Is A Real Bug
The request handle is guest-controlled input. Invalid-handle cases are expected runtime conditions and the ABI declares an error return, not a trap. Panicking here creates observable behavior inconsistent with adjacent hostcalls and allows a guest to force host-side trapping through a stale handle reuse sequence.

## Fix Requirement
Replace the `unwrap()` on `request_parts` with error propagation so invalid or closed handles return `types::Error`.

## Patch Rationale
The patch changes `get_header_values` to use `?` when resolving the request handle, aligning it with adjacent methods and the older ABI implementation. This preserves the declared interface contract and removes the panic path without changing successful behavior.

## Residual Risk
None

## Patch
- Patch file: `015-get-header-values-panics-on-invalid-request-handle.patch`
- Change: update `src/component/compute/http_req.rs` so `get_header_values` propagates `request_parts` failure with `?` instead of calling `unwrap()`.