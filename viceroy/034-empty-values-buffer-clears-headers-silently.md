# Empty values buffer clears headers silently

## Classification
- Type: data integrity bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `src/wiggle_abi/headers.rs:121`

## Summary
`values_set` accepts a guest-controlled `values` byte slice, parses it into header values, removes all existing entries for the target header, and then appends the parsed replacements. When the guest supplies a zero-length `values` buffer, parsing yields no values, but removal still occurs. The call succeeds and silently clears the existing header.

## Provenance
- Verified by reproduction against the repository code
- Scanner source: https://swival.dev
- ABI reachability confirmed in `wasm_abi/compute-at-edge-abi/compute-at-edge.witx:325`
- ABI reachability confirmed in `wasm_abi/compute-at-edge-abi/compute-at-edge.witx:902`
- Raw pointer/length forwarding confirmed in `wasm_abi/adapter/src/fastly/core.rs:1941`
- Raw pointer/length forwarding confirmed in `wasm_abi/adapter/src/fastly/core.rs:2839`
- Mirrored behavior confirmed in `src/component/compute/http_req.rs:261`
- Mirrored behavior confirmed in `src/component/compute/http_resp.rs:195`

## Preconditions
- The target header already exists
- The guest invokes the header-values-set API with an empty `values` buffer

## Proof
At `src/wiggle_abi/headers.rs:121`, `values_set` reads guest bytes from `memory.as_slice(values)` and parses them by splitting on NUL before collecting into `Vec<HeaderValue>`. For an empty slice, this produces an empty vector. The function then removes existing entries with `remove_entry_mult()` and appends nothing because the parsed set is empty. No error is returned. Because the ABI accepts `(list char8)` and the adapter forwards raw pointer/length pairs without rejecting `values_len == 0`, this path is reachable from guest code.

## Why This Is A Real Bug
This is not a benign edge case. The API contract is a setter for header values, but an empty serialized buffer acts as an implicit delete operation. That bypasses the explicit remove API and causes silent state loss. The impact is practical: callers can accidentally erase security- or routing-relevant headers such as authorization, cache, or forwarding metadata if serialization produces an empty buffer.

## Fix Requirement
Reject empty `values` input, or defer removal of existing header entries until after at least one replacement value has been successfully parsed and validated.

## Patch Rationale
The patch in `034-empty-values-buffer-clears-headers-silently.patch` prevents the delete-on-empty behavior by requiring at least one parsed header value before mutating existing state. This preserves setter semantics, ensures empty input is not treated as a silent clear, and aligns behavior with the expectation that deletion must be explicit.

## Residual Risk
None

## Patch
- Patch file: `034-empty-values-buffer-clears-headers-silently.patch`
- Effect: prevents zero-length `values` buffers from clearing existing headers without an explicit removal call