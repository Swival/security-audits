# get_body rejects second readers after spawning an untracked body stream

## Classification
- Type: resource lifecycle bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `src/wiggle_abi/cache.rs:430`
- `src/component/compute/cache.rs:348`

## Summary
`get_body` creates a new cache body stream before enforcing the single-reader rule. When a prior body handle is still live, the call returns `HandleBodyUsed`, but the newly created `Body` is never inserted into session state or otherwise tracked. That leaves the spawned stream task and associated watch subscription alive until the cache body progresses, completes, errors, or is dropped elsewhere.

## Provenance
- Verified from the provided reproduction and source inspection
- Scanner: https://swival.dev

## Preconditions
- A cached entry exists
- A previous body handle for that cached entry is still open in the session

## Proof
At `src/wiggle_abi/cache.rs:430`, `entry.body(from, to).await?` runs before the exclusivity check against `found.last_body_handle`. The rejection path then evaluates `self.body(prev_handle).is_ok()` and returns `HandleBodyUsed` if the prior reader is still alive. Because the fresh `body` was already created and is never stored in session state on that path, it is abandoned immediately after creation.

The same ordering exists in `src/component/compute/cache.rs:348`, where a new body is created before checking whether `found.last_body_handle` still resolves to a live handle.

This is practically reachable: successful calls record `last_body_handle` at `src/wiggle_abi/cache.rs:608`, and later calls only test liveness with `self.body(prev_handle).is_ok()` at `src/wiggle_abi/cache.rs:603`. Repeated `get_body` calls while the first handle remains open deterministically take the rejection path after creating another stream.

## Why This Is A Real Bug
The rejection path violates the intended resource lifecycle. The newly spawned body stream is not returned to the guest, not registered for later cleanup, and not cancelled before returning the error. Each rejected call therefore retains unnecessary runtime resources. For long-lived or stalled cache bodies, these retained tasks and subscriptions can accumulate without bound during the lifetime of the original open reader.

## Fix Requirement
Enforce single-reader exclusivity before calling `entry.body(...)`, or explicitly cancel and drop the newly created stream before returning `HandleBodyUsed`.

## Patch Rationale
The patch should reorder operations so the existing-body-handle liveness check happens before any new body stream is spawned. That preserves behavior while eliminating the abandoned-stream path. The same correction is required in both the wiggle ABI path and the component host path because they share the same bug pattern.

## Residual Risk
None

## Patch
- File: `004-get-body-leaks-a-spawned-body-stream-on-single-reader-reject.patch`
- Effect: moves the single-reader rejection check ahead of `entry.body(...)` in both affected implementations so no new body stream is created on a rejected second-reader request